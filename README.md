# CRBC

CRBC analyzes Verilog/SystemVerilog RTL for potential security defects. It extracts structured specifications from RTL chunks, retrieves semantic assumption–guarantee pairs with BGE-M3, generates candidate findings, optionally attaches design-document evidence, and reviews selected candidates against the source tree.

The pipeline has four stages:

| Stage | What it does |
| --- | --- |
| Specification extraction | Turns each RTL chunk into structured guarantees, assumptions, and uncertain points. |
| Retrieval | Pairs assumptions with guarantees across chunks and specifications (BGE-M3 dense embeddings plus signal-name relations). |
| **Consistency analyzer (CA)** | Decides, for each pair, whether the guarantee contradicts, leaves a gap in, or defensively handles the assumption. |
| **Source-level arbiter** | Reads the actual RTL for each selected candidate and returns a verdict with source evidence. |

Throughout the code, the source-level arbiter stage keeps its original `phase3` identifier in flags, module paths, and output directories.

This repository contains the runtime source, prompts, an output schema, and offline checks. Supply your own RTL tree, API credentials, and embedding model.

## 1. Install

Linux and **Python 3.12** are recommended. Run these commands from the repository root:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

# CPU example. For CUDA, install the matching PyTorch wheel instead.
python -m pip install 'torch==2.7.1' --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements.txt
```

`requirements.txt` lists the direct dependencies: `numpy`, `torch`, `FlagEmbedding`, and `requests`. CRBC uses `FlagEmbedding.BGEM3FlagModel` directly; its transformer and hub dependencies are resolved by pip. Use the [PyTorch installation selector](https://pytorch.org/get-started/locally/) for a wheel appropriate for your driver. An OpenAI Python SDK or `python-dotenv` installation is not needed.

Source-level review also requires the **Codex CLI** and a model/provider supporting its Responses API and tool use. The controller's CLI interface was checked with **codex-cli 0.166.0**:

```bash
# Requires Node.js/npm compatible with this CLI release.
npm install -g @openai/codex@0.166.0
codex --version
```

The CLI is unnecessary for `--phase3 skip` or a standalone `--prepare-only` run. Simulation and formal-verification tools are not required by this pipeline.

## 2. Configure model APIs

```bash
cp .env.example .env
# Edit .env with your provider's values.
```

The main configuration is:

```dotenv
CRBC_OPENAI_API_KEY=your-api-key
CRBC_OPENAI_BASE_URL=https://your-provider.example/v1
CRBC_OPENAI_MODEL=your-chat-model
```

`BASE_URL` is the API root, usually ending in `/v1`. The Python client appends `/chat/completions`. Specification extraction, retrieval, and reference atoms use **Chat Completions**. The model must accept `temperature` and `max_tokens` and return the requested structured content. Token limits must fit your provider; use `--spec-max-tokens`, `--channel-b-max-tokens`, and `--ref-max-tokens` to adjust them.

Source-level review uses **Responses** through Codex CLI. A gateway that only implements Chat Completions cannot run that stage. For a separate review provider/model, add:

```dotenv
CRBC_REVIEW_API_KEY=your-review-api-key
CRBC_REVIEW_BASE_URL=https://your-responses-provider.example/v1
CRBC_REVIEW_MODEL=your-tool-capable-review-model
```

Then pass `--phase3-provider CRBC_REVIEW` to `run_crbc.py`. Otherwise all stages use `CRBC_OPENAI`. The controller creates isolated CLI configuration from these values; it does not require copying a personal Codex configuration into the repository. `CRBC_PHASE3_MODEL` can override the review model. When intentionally requesting a model different from the provider's `MODEL`, use the standalone arbiter with `--model ... --allow-provider-model-mismatch`.

Configuration precedence is **process environment variables → selected dotenv file**. Select a file with `--env-file /path/to/config.env` or `ENV_FILE`; the default is `.env` beside this README. Use plain `KEY=value` lines: shell expansion and inline comments are not supported. Set device/cache settings in the process environment or CLI flags as shown below.

The runner defaults to `--thinking none`, which omits the provider-specific `thinking` field. Enable `low`, `medium`, or `high` only when your Chat Completions provider supports it. Source-level review has its own reasoning configuration.

Real runs send selected RTL/specification and reference content to configured providers and consume API quota. `.env` is ignored by Git.

## 3. Prepare BGE-M3

Retrieval uses the dense embeddings of **BAAI/bge-m3**, including when reference augmentation is disabled. Download the model once:

```bash
hf download BAAI/bge-m3 --local-dir /path/to/models/bge-m3
```

Pass `--semantic-model /path/to/models/bge-m3` to use this local directory. The main weight file is about 2.3 GB; allow additional disk space for tokenizer files, dependencies, and runtime caches. Memory requirements depend on device and batch size.

Alternatively, use the default model ID with `--online-download-model`. The cache location is selected by `--semantic-hf-home`, then `HF_HOME`, then `.cache/huggingface` under this repository. Network model downloads are **disabled by default**. A cache populated elsewhere must use the same cache location, or supply a local model directory explicitly.

CRBC uses CUDA when available and otherwise CPU. To force CPU or reduce embedding batch memory:

```bash
export CRBC_SEMANTIC_DEVICE=cpu
# Add --semantic-batch-size 2 to the run command if needed.
```

Do not combine `--online-download-model` with `HF_HUB_OFFLINE=1` or `TRANSFORMERS_OFFLINE=1`.

## 4. Run on your RTL

Set the following paths to your checkout and model directory. No source file needs editing to change these paths.

```bash
RTL_ROOT=/path/to/your/rtl-repository
BGE_MODEL=/path/to/models/bge-m3
RUN_DIR="$PWD/output/demo"

# Inspect local paths and commands first. No outputs or API calls are made.
python scripts/run_crbc.py \
  --module demo \
  --repo-root "$RTL_ROOT" \
  --rtl-dir rtl \
  --out-dir "$RUN_DIR" \
  --no-ref \
  --semantic-model "$BGE_MODEL" \
  --dry-run

# Run extraction, candidate analysis, and source review.
python scripts/run_crbc.py \
  --module demo \
  --repo-root "$RTL_ROOT" \
  --rtl-dir rtl \
  --out-dir "$RUN_DIR" \
  --no-ref \
  --semantic-model "$BGE_MODEL"
```

`--module` is an output label containing letters, digits, and underscores. `--rtl-dir` is relative to `--repo-root`, or an absolute directory inside it. Without a file list, the chunker reads every immediate `*.sv` and `*.v` file in that directory. It does not recursively enumerate the repository or elaborate a build configuration.

For precise selection, pass `--rtl-file-list /path/to/files.txt`. Each nonempty line names one `.sv` or `.v` file, absolute or relative to `--repo-root`; lines beginning with `#` are ignored. For example:

```text
rtl/demo.sv
rtl/submodule/controller.sv
```

By default, chunking is local. `--prefilter` adds an LLM step to filter structural sections. `--workers` controls extraction/candidate workers; `--concurrency` and `--shard-size` control source-review workers and shard sizes.

Choose one reference mode:

| Argument | Reference input |
| --- | --- |
| `--no-ref` | Analyze without design-document augmentation. |
| `--ref-ip-root /path/to/opentitan/hw/ip` | Read the module's OpenTitan-style documentation and HJSON. |
| `--ref-fragment-index /path/to/fragment_index.json` | Read verified primary fragments from a provenance index; see [config/README.md](config/README.md). |

For an OpenTitan checkout, replace the path values below:

```bash
OPENTITAN_ROOT=/path/to/opentitan
python scripts/run_crbc.py \
  --module uart \
  --repo-root "$OPENTITAN_ROOT" \
  --rtl-dir hw/ip/uart/rtl \
  --out-dir "$PWD/output/uart" \
  --ref-ip-root "$OPENTITAN_ROOT/hw/ip" \
  --semantic-model "$BGE_MODEL"
```

With reference augmentation, `--module` must match the documentation/index module name. The OpenTitan adapter normally reads `data/*.hjson` and `doc/theory_of_operation.md`, with module-specific exceptions in `rtl_bug_agent/phase2/ref_extract.py`. Check these exceptions when using a source revision whose layout differs.

Source-review modes in the combined runner:

| Mode | Behavior |
| --- | --- |
| `--phase3 run` | Default: all stages, including source-level review through Codex CLI. |
| `--phase3 prepare` | Run extraction and retrieval, then freeze review inputs without Codex. Those stages still call APIs and load BGE. |
| `--phase3 skip` | Run extraction and retrieval only. |
| `--dry-run` | Print commands only; no API calls, model loading, or output creation. |

After a combined `prepare` or `skip` run, continue review with the standalone `scripts/run_phase3.py` command in Section 6. Changing the combined runner's `--phase3` mode changes its configuration fingerprint and requires a new output directory. A prepared run can be resumed with the same run ID only when its frozen provider/model and other inputs match.

## 5. Outputs, review policy, and resuming

The selected output directory contains:

```text
output/demo/
  .crbc_run.json                     # input/configuration fingerprint
  demo_chunks.json
  specs_demo/                       # structured chunk specifications
  .semantic_ag_cache/               # cached retrieval data
  .checkpoint_demo_B_semantic.json   # candidate checkpoints
  semantic_ag_shadow_demo.json       # retrieval diagnostics
  ref_out/                          # reference atoms/checkpoints, when enabled
  findings_demo.json                # candidates and reference clues
  phase3/phase3_runs/review/
    ...                             # frozen inputs, checkpoints, worker attempts
    demo/phase3_results.json         # source-review verdicts
```

The source-level arbiter normally selects findings with `HIGH` severity **or** nonempty `ref_clues`. Other candidates remain in `findings_<module>.json` and have not received this source review. The standalone controller supports `--force-finding FINDING_ID` to include another finding.

Review verdicts are `CONFIRMED`, `FALSE_ALARM`, `NEEDS_MORE_CONTEXT`, and `UNCERTAIN`. `CONFIRMED` requires three checks to pass on the reviewed RTL:

- **Validity** — the defect construct is present at the quoted source location with the stated root cause.
- **Reachability** — its trigger preconditions can be met in the configuration under review.
- **Effect** — triggering it has a concrete security consequence.

A real but unreachable construct is not `CONFIRMED`; the arbiter records the construct and the blocking precondition so the decision stays auditable. `CONFIRMED` is therefore a source-review verdict, not a simulation or formal proof. Read [the review policy](config/prompts/phase3/verify_agent.md) before using these labels for evaluation.

Rerun the same command to reuse successful specification, candidate, and document checkpoints. The combined runner rejects an output directory with a different input/configuration fingerprint or an unrecognized nonempty directory. Use a **new `--out-dir`** when changing RTL, documentation, prompts, models, or generation settings. Keep the same paths and inputs for a resumed run. Source review also freezes hashes under its run ID and rejects input drift; changing a review model/prompt requires a new run ID, and the combined runner additionally requires a new output directory.

The runner stops before candidate analysis if specification generation is incomplete. Inspect failed/error specification files and API configuration, then rerun.

## 6. Run stages separately

These commands use the same runtime components as the combined runner. Run them from the repository root. Lower-level scripts expose checkpoint/retrieval controls through `--help`; manage input changes and cached outputs yourself when using them.

```bash
# 1a. Local RTL chunking.
python -m rtl_bug_agent.cli chunk \
  --rtl-dir "$RTL_ROOT/rtl" --out "$RUN_DIR/demo_chunks.json"

# 1b. Specification extraction (API).
python scripts/generate_all_specs.py \
  --chunks "$RUN_DIR/demo_chunks.json" --out-dir "$RUN_DIR/specs_demo" \
  --env-file .env --provider CRBC_OPENAI --thinking none

# 2. Retrieval and candidates (BGE + API).
python scripts/run_phase2_e2e.py \
  --ip demo --out-root "$RUN_DIR" --specs-dir "$RUN_DIR/specs_demo" \
  --semantic-model "$BGE_MODEL" --no-ref-augment \
  --env-file .env --provider CRBC_OPENAI --thinking none

# Source review, preparation only: no model/CLI/credentials needed.
python scripts/run_phase3.py \
  --repo-root "$RTL_ROOT" --out-root "$RUN_DIR" \
  --run-root "$RUN_DIR/phase3" --modules demo --run-id review \
  --prepare-only

# Source-level review (Responses API).
python scripts/run_phase3.py \
  --repo-root "$RTL_ROOT" --out-root "$RUN_DIR" \
  --run-root "$RUN_DIR/phase3" --modules demo --run-id review \
  --env-file .env --provider-env-prefix CRBC_OPENAI
```

If preparation is done without a configured model, use a new run ID when starting a model-configured review, since the model is part of the frozen configuration. `--modules` can be omitted to discover `findings_*.json` in `--out-root`. Review workers use a read-only source sandbox; controller artifacts go under `--run-root`. The optional `--phase3-top-n` in `run_phase2_e2e.py` invokes a separate lightweight reviewer; the combined runner uses the standalone controller instead.

Other utilities:

- `scripts/extract_ref.py`: extract reference atoms separately.
- `scripts/run_ref_match.py`: attach atoms to findings for one or more modules.
- `scripts/materialize_refs.py`: build/verify fragments from a supplied manifest; see [config/README.md](config/README.md).

## 7. Offline verification and troubleshooting

```bash
# Syntax, CLI, and synthetic pipeline checks; no real APIs or weights.
bash smoke_test.sh
```

`smoke_test.sh` works from another working directory and accepts `PYTHON=/path/to/python`. It uses temporary synthetic RTL/findings and removes temporary outputs. These checks validate local interfaces and preparation, not remote model quality or a fresh dependency installation.

| Symptom | Check |
| --- | --- |
| Missing API variables | Check `--env-file` and provider prefix; process variables override the file. |
| API request/JSON errors | Check endpoint, model capabilities, token limits, and timeout. Use `--thinking none` for providers without that extension. |
| Source review cannot call the model | Confirm Responses/tool support, CLI version, and review provider configuration. |
| BGE unavailable offline | Supply a complete local model directory, use the correct HF cache, or explicitly allow a download. |
| Embedding out of memory | Lower `--semantic-batch-size` or set `CRBC_SEMANTIC_DEVICE=cpu`. |
| No chunks | Check that `--rtl-dir` contains immediate `*.sv`/`*.v` files, or provide a file list. |
| Fingerprint/input drift | Start a new output directory or review run ID as described above. |
| Reference extraction halted | Inspect the extraction errors recorded in `<ip>_ref_raw.json`. |

## Repository layout

```text
rtl_bug_agent/    Reusable RTL, LLM, specification, retrieval, and review code
scripts/          CLI entry points and pipeline runner
config/           Prompts, review schema, and fragment-format documentation
.env.example      API configuration template
requirements.txt  Python dependencies
smoke_test.sh     Portable offline self-check
LICENSE           Apache License 2.0
```

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
