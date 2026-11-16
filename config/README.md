# Runtime configuration and document fragments

The main API setup and pipeline commands are documented in the [root README](../README.md).

## Prompts and schema

| File | Purpose |
| --- | --- |
| `prompts/chunk_spec_agu_structured_slim_en.md` | Structured specifications from RTL chunks. |
| `prompts/phase2/channel_b_ag_pairing.md` | Consistency analyzer: candidate generation from assumption–guarantee pairs. |
| `prompts/phase2/ref_extract.md` | Design-document reference atom extraction. |
| `prompts/phase3/verify_agent.md` | Source-level arbiter: review policy and evidence requirements. |
| `phase3_schema.json` | Structured worker output contract. |

The optional RTL prefilter uses a built-in prompt in `rtl_bug_agent/rtl/prefilter.py`. To override it, create `config/prompts/rtl_prefilter.md`. The source-level arbiter also accepts an explicit `--prompt` and `--schema` in its standalone CLI. Use fresh outputs after changing prompts.

## Reference fragment materializer

Use `scripts/materialize_refs.py` when a module's specification is distributed across shared Markdown documents. It selects exact heading subtrees, preserves their original bytes, writes module-specific documentation, and creates a provenance index for extraction. Prepare a manifest for your own source tree.

The manifest uses `schema_version: 2`. The source-root field is named **`caliptra_root`** because this adapter originated with that document layout; it must be supplied even for another tree. Use an absolute path. Source and target paths are relative to that root. `fragment_index` is relative to the manifest's directory and must remain within it.

A minimal manifest is shown below. Replace the root and hashes for your own documents. In this synthetic example, `docs/spec.md` contains exactly the UTF-8 bytes `# Demo\nThe control register must remain locked after reset.\n`, so its whole-file hash and the selected heading-subtree hash coincide.

```json
{
  "schema_version": 2,
  "caliptra_root": "/path/to/your/source-tree",
  "source_order": ["hardware"],
  "sources": {
    "hardware": {
      "path": "docs/spec.md",
      "sha256": "598602a33a9b48215d64bb8fa410bbc73870580ee21ff11cdc2db1a2382e168f"
    }
  },
  "fragment_index": "fragment_index.json",
  "targets": [
    {
      "ip": "demo",
      "output": "src/demo/config/demo.md",
      "classification": "primary",
      "extractable": true,
      "fragments": [
        {
          "source": "hardware",
          "heading_path": ["Demo"],
          "sha256": "598602a33a9b48215d64bb8fa410bbc73870580ee21ff11cdc2db1a2382e168f"
        }
      ]
    }
  ],
  "skipped": {},
  "retirements": []
}
```

Each `heading_path` is the complete Markdown heading ancestry, for example `["Hardware", "Registers", "Locking"]`. The selected subtree includes its heading and descendants up to the next heading of equal or higher level. Use SHA-256 of the original bytes, retaining line endings. Source ordering must follow `source_order`, then document position. Target IP names are unique, output basenames must be `<ip>.md`, and output parent directories must already exist.

From the repository root:

```bash
# Read-only: validate sources/hashes and inspect selected fragments.
python scripts/materialize_refs.py --manifest /path/to/manifest.json --plan

# Read-only: additionally require fresh output/index paths.
python scripts/materialize_refs.py --manifest /path/to/manifest.json --check

# Write module documents inside the supplied source tree, plus the index.
python scripts/materialize_refs.py --manifest /path/to/manifest.json --apply

# Read-only: compare managed outputs/index with the manifest.
python scripts/materialize_refs.py --manifest /path/to/manifest.json --verify
```

`--apply` refuses output collisions. For an already managed set, `--regenerate` updates documents and the index after checking existing output hashes against the prior index or a supplied target `legacy_sha256`. Optional `retirements` name old managed outputs and require their `legacy_sha256`; regeneration removes those files. Use an empty retirement list when none are intended. Both write modes stage changes and restore managed files if an operation fails.

## Fragment index consumed by extraction

Pass the generated index to `run_crbc.py --ref-fragment-index ...` or `run_phase2_e2e.py --ref-fragment-index ...`. The index has `schema_version: 1`, `caliptra_root`, and a `fragments` array. Each record identifies its module, original source/hash, complete heading path, line/byte ranges, content hash, and generated output/byte range. The extractor checks source and content hashes before model calls.

Generate the index with the materializer rather than maintaining byte offsets manually. Only records with `classification: "primary"` and `extractable: true` become reference extraction inputs. `architecture_context` records must have `extractable: false`; they remain provenance records. Module names must match the pipeline's `--module`/`--ip` argument. Changing source documents requires updating the manifest hashes and regenerating the index.
