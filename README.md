# CRBC

CRBC (Cross-Region Behavioural Consistency Checking) is an LLM-assisted framework for detecting bugs in Verilog/SystemVerilog RTL. It compares related behaviours across RTL regions and examines bug candidates against the source code. Design documents can provide additional evidence when available.

## Installation

Linux and Python 3.12 are recommended. Node.js/npm is required to install Codex CLI for source-level examination.

```bash
git clone https://github.com/Jaylen666/CRBC.git
cd CRBC

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip

# CPU installation. For CUDA, install the matching PyTorch wheel instead.
python -m pip install 'torch==2.7.1' --index-url https://download.pytorch.org/whl/cpu
python -m pip install -r requirements.txt

npm install -g @openai/codex@0.166.0
```

For a CUDA installation, choose the appropriate wheel from the [PyTorch installation guide](https://pytorch.org/get-started/locally/).

## API configuration

Create a local configuration file:

```bash
cp .env.example .env
```

Fill in these values in `.env`:

```dotenv
CRBC_OPENAI_API_KEY=your-api-key
CRBC_OPENAI_BASE_URL=https://your-provider.example/v1
CRBC_OPENAI_MODEL=your-model
```

The provider must support Chat Completions. Source-level examination also requires a tool-capable model with Responses API support.

To use a separate provider for source-level examination, uncomment and fill in the `CRBC_REVIEW_*` entries in `.env`. Add `--phase3-provider CRBC_REVIEW` to your run command.

## Run CRBC

Replace `/path/to/rtl-repository` with your RTL checkout and `rtl` with the directory to analyse:

```bash
python scripts/run_crbc.py \
  --module demo \
  --repo-root /path/to/rtl-repository \
  --rtl-dir rtl \
  --out-dir output/demo \
  --no-ref \
  --online-download-model
```

This command downloads BGE-M3 if needed and runs the analysis without design documents. To use an existing local model, replace `--online-download-model` with `--semantic-model /path/to/bge-m3`.

`--rtl-dir` must be inside `--repo-root`. By default, only `.sv` and `.v` files directly in that directory are included. To select files across subdirectories, add `--rtl-file-list /path/to/files.txt`, with one file per line, relative to `--repo-root` or absolute.

To include OpenTitan design documents, use the following command:

```bash
python scripts/run_crbc.py \
  --module uart \
  --repo-root /path/to/opentitan \
  --rtl-dir hw/ip/uart/rtl \
  --out-dir output/uart \
  --ref-ip-root /path/to/opentitan/hw/ip \
  --online-download-model
```

For other document layouts, see the [reference-fragment setup](config/README.md) and use `--ref-fragment-index /path/to/fragment_index.json` instead of `--no-ref`.

### Common options

| Option | Use |
| --- | --- |
| `--dry-run` | Preview the commands without calling APIs, loading models, or creating outputs. |
| `--phase3 skip` | Stop after candidate generation; Codex CLI is not needed. |
| `--phase3-provider CRBC_REVIEW` | Use the separate examination provider configured in `.env`. |
| `--workers 4` | Set the number of workers for behaviour extraction and consistency analysis. |
| `--concurrency 3` | Set the number of workers for source-level examination. |
| `--semantic-batch-size 2` | Reduce the embedding batch size when memory is limited. |
| `--env-file /path/to/config.env` | Use another API configuration file. |

Set `CRBC_SEMANTIC_DEVICE=cpu` to use CPU embeddings when needed.

## Results and resuming

For the `demo` example, the main results are:

| File | Contents |
| --- | --- |
| `output/demo/findings_demo.json` | Bug candidates. |
| `output/demo/phase3/phase3_runs/review/demo/phase3_results.json` | Examination results for selected candidates. |

Rerun the same command to resume an interrupted run. Use a new `--out-dir` after changing the RTL, documents, models, or configuration.

## Checks and help

```bash
# Offline checks; no API credentials or model weights are needed.
bash smoke_test.sh

# Show all runner options.
python scripts/run_crbc.py --help
```

## License

Released under the [Apache License 2.0](LICENSE).
