#!/usr/bin/env python3
"""Run CRBC on a user-supplied RTL tree with explicit inputs and output paths."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUN_IDENTITY = ".crbc_run.json"


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--module", required=True, help="A label for this module's outputs.")
    ap.add_argument("--repo-root", type=Path, required=True, help="Repository containing the RTL and review context.")
    ap.add_argument("--rtl-dir", type=Path, required=True, help="RTL directory; relative paths are resolved under --repo-root.")
    ap.add_argument("--rtl-file-list", type=Path, help="Optional newline-delimited file list; entries are relative to --repo-root or absolute.")
    ap.add_argument("--out-dir", type=Path, required=True, help="A dedicated output directory; reuse only for the same inputs/configuration.")
    refs = ap.add_mutually_exclusive_group(required=True)
    refs.add_argument("--ref-ip-root", type=Path, help="OpenTitan-style hw/ip directory containing the module's documentation.")
    refs.add_argument("--ref-fragment-index", type=Path, help="Caller-supplied reference fragment index.")
    refs.add_argument("--no-ref", action="store_true", help="Run without reference-document augmentation.")
    ap.add_argument("--env-file", type=Path, default=Path(os.environ.get("ENV_FILE") or PROJECT_ROOT / ".env"))
    ap.add_argument("--provider", default="CRBC_OPENAI", help="Chat Completions API environment prefix.")
    ap.add_argument("--thinking", default="none", choices=["none", "low", "medium", "high"])
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=600, help="HTTP timeout in seconds.")
    ap.add_argument("--spec-max-tokens", type=int, default=50000)
    ap.add_argument("--channel-b-max-tokens", type=int, default=10000)
    ap.add_argument("--ref-max-tokens", type=int, default=30000)
    ap.add_argument("--prefilter", action="store_true", help="Enable the existing LLM structural prefilter during chunking.")
    ap.add_argument("--semantic-model", default="BAAI/bge-m3", help="HuggingFace model ID or local model directory.")
    ap.add_argument("--semantic-hf-home", type=Path, default=Path(os.environ.get("HF_HOME") or PROJECT_ROOT / ".cache/huggingface"))
    ap.add_argument("--semantic-batch-size", type=int, default=16)
    ap.add_argument("--online-download-model", action="store_true", help="Allow HuggingFace model downloads (offline by default).")
    ap.add_argument("--phase3", choices=["run", "prepare", "skip"], default="run", help="Run source review, prepare its inputs offline, or stop after Phase 2.")
    ap.add_argument("--phase3-provider", help="Responses API prefix; defaults to --provider.")
    ap.add_argument("--phase3-model", help="Optional explicit review model; otherwise use its provider's MODEL.")
    ap.add_argument("--phase3-prompt", type=Path, help="Optional source-review prompt override.")
    ap.add_argument("--codex-bin", default="codex")
    ap.add_argument("--concurrency", type=int, default=3, help="Phase 3 worker concurrency (1-50).")
    ap.add_argument("--shard-size", type=int, default=20, help="Phase 3 findings per shard (1-40).")
    ap.add_argument("--run-id", default="review", help="Phase 3 checkpoint run ID.")
    ap.add_argument("--dry-run", action="store_true", help="Print commands without loading models, calling APIs, or creating outputs.")
    return ap


def check_specs(chunks_path: Path, specs_dir: Path) -> None:
    """Stop before candidate analysis when spec generation is incomplete."""
    sys.path.insert(0, str(PROJECT_ROOT))
    from rtl_bug_agent.rtl.io import read_chunks
    from scripts.generate_all_specs import _separate_chunks

    normal, batched = _separate_chunks(read_chunks(chunks_path))
    expected = normal + batched
    if not expected:
        raise RuntimeError("No RTL chunks were generated; check the selected files and RTL directory.")
    expected_ids = {chunk.chunk_id for chunk in expected}
    if len(expected_ids) != len(expected):
        raise RuntimeError("Selected files produced duplicate chunk IDs; analyze conflicting module names in separate output directories")
    failed = []
    for chunk in expected:
        path = specs_dir / f"{chunk.chunk_id}.json"
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            value = None
        if (not isinstance(value, dict) or "error" in value
                or value.get("chunk_id") != chunk.chunk_id
                or value.get("source_file") != chunk.source_file
                or value.get("line_start") != chunk.line_start
                or value.get("line_end") != chunk.line_end
                or any(not isinstance(value.get(key), list)
                       for key in ("guarantees", "assumptions", "uncertain_points"))):
            failed.append(chunk.chunk_id)
    if failed:
        raise RuntimeError(f"Spec generation incomplete ({len(failed)}/{len(expected)}): {', '.join(failed[:10])}")
    unexpected = [path.name for path in specs_dir.glob("*.json")
                  if not path.name.startswith((".", "_", "findings_", "semantic_"))
                  and path.stem not in expected_ids]
    if unexpected:
        raise RuntimeError(f"Unexpected spec files would contaminate candidate analysis: {', '.join(sorted(unexpected)[:10])}")


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_identity(args: argparse.Namespace, repo: Path, rtl: Path,
                 selected_files: list[str] | None, env_file: Path) -> dict:
    """Bind resumable checkpoints to their inputs and generation settings."""
    paths = ([Path(path) for path in selected_files] if selected_files is not None
             else sorted([*rtl.glob("*.sv"), *rtl.glob("*.v")]))
    inputs = {str(path): _file_hash(path) for path in sorted(set(paths))}
    if args.ref_fragment_index:
        index_path = args.ref_fragment_index
        inputs[str(index_path)] = _file_hash(index_path)
        index = json.loads(index_path.read_text(encoding="utf-8"))
        source_root = Path(index.get("caliptra_root", "")).expanduser()
        if not source_root.is_absolute():
            source_root = index_path.parent / source_root
        for record in index.get("fragments", []):
            if record.get("ip") == args.module and record.get("extractable") is True:
                source = (source_root / record["source_path"]).resolve()
                inputs[str(source)] = _file_hash(source)
    elif args.ref_ip_root:
        # Include aliases/shared docs as well as the selected module's docs.
        for path in sorted(args.ref_ip_root.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".md", ".hjson"}:
                inputs[str(path)] = _file_hash(path)
    config = {key: str(value) if isinstance(value, Path) else value
              for key, value in vars(args).items()
              if key not in {"dry_run", "out_dir", "rtl_file_list"}}
    config["repo_root"], config["rtl_dir"] = str(repo), str(rtl)
    # Record whether the file list or directory discovery supplied the inputs.
    config["explicit_file_selection"] = selected_files is not None
    # Resolve provider/model overrides without loading dotenv into this process.
    dotenv = {}
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                dotenv[key.strip()] = value.strip().strip('"').strip("'")
    provider_settings = {}
    for prefix in {args.provider, args.phase3_provider or args.provider}:
        for suffix in ("BASE_URL", "MODEL"):
            key = f"{prefix.upper()}_{suffix}"
            provider_settings[key] = os.environ.get(key, dotenv.get(key))
    # Model artifacts can be large; track local directory metadata without
    # loading weights or importing the embedding framework.
    model = Path(args.semantic_model)
    model_files = {}
    if model.is_dir():
        model_files = {str(path.relative_to(model)): [path.stat().st_size, path.stat().st_mtime_ns]
                       for path in sorted(model.rglob("*")) if path.is_file()}
    implementation = {}
    for directory in (PROJECT_ROOT / "rtl_bug_agent", PROJECT_ROOT / "config/prompts"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".md"}:
                implementation[str(path.relative_to(PROJECT_ROOT))] = _file_hash(path)
    for name in ("run_crbc.py", "generate_all_specs.py", "run_phase2_e2e.py", "run_phase3.py"):
        path = PROJECT_ROOT / "scripts" / name
        implementation[f"scripts/{name}"] = _file_hash(path)
    if args.phase3_prompt:
        inputs[str(args.phase3_prompt)] = _file_hash(args.phase3_prompt)
    payload = {"schema_version": 1, "inputs": inputs, "config": config,
               "provider_settings": provider_settings, "model_files": model_files,
               "implementation": implementation}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {"schema_version": 1, "fingerprint": digest}


def check_run_identity(out: Path, identity: dict, *, create: bool = False) -> None:
    """Reject stale/untracked outputs before a child process can reuse them."""
    marker = out / RUN_IDENTITY
    if marker.exists():
        try:
            previous = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Cannot read output identity {marker}; use a new --out-dir") from exc
        if previous != identity:
            raise RuntimeError("Output inputs/configuration changed; use a new --out-dir to avoid reusing stale checkpoints")
    elif out.exists() and any(out.iterdir()):
        raise RuntimeError("Output directory contains untracked files; use a new or empty --out-dir")
    elif create:
        out.mkdir(parents=True, exist_ok=True)
        with marker.open("x", encoding="utf-8") as handle:
            json.dump(identity, handle, indent=2)
            handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    ap = parser()
    args = ap.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9_]+", args.module):
        ap.error("--module must contain only letters, digits, and underscores")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.run_id) or args.run_id in {".", ".."}:
        ap.error("--run-id must be a single directory name")
    if min(args.workers, args.timeout, args.semantic_batch_size, args.spec_max_tokens,
           args.channel_b_max_tokens, args.ref_max_tokens) < 1:
        ap.error("worker, timeout, batch, and token limits must be positive")
    if not 1 <= args.concurrency <= 50 or not 1 <= args.shard_size <= 40:
        ap.error("--concurrency must be 1-50 and --shard-size must be 1-40")
    repo = args.repo_root.expanduser().resolve()
    rtl = args.rtl_dir.expanduser()
    rtl = (rtl if rtl.is_absolute() else repo / rtl).resolve()
    out = args.out_dir.expanduser().resolve()
    env_file = args.env_file.expanduser().resolve()
    if not repo.is_dir() or not rtl.is_dir():
        ap.error("--repo-root and --rtl-dir must be existing directories")
    if not rtl.is_relative_to(repo):
        ap.error("--rtl-dir must be inside --repo-root")
    if out == repo or repo.is_relative_to(out) or out.is_relative_to(rtl):
        ap.error("--out-dir must not contain the RTL repository or be inside its RTL directory")
    for path, label in [(args.ref_ip_root, "--ref-ip-root"), (args.ref_fragment_index, "--ref-fragment-index"),
                        (args.rtl_file_list, "--rtl-file-list"), (args.phase3_prompt, "--phase3-prompt")]:
        if path and not path.expanduser().exists():
            ap.error(f"{label} does not exist: {path}")
    for field in ("ref_ip_root", "ref_fragment_index", "rtl_file_list", "phase3_prompt"):
        value = getattr(args, field)
        if value is not None:
            setattr(args, field, value.expanduser().resolve())
    if args.ref_ip_root and not args.ref_ip_root.is_dir():
        ap.error("--ref-ip-root must be a directory")
    for field in ("ref_fragment_index", "rtl_file_list", "phase3_prompt"):
        value = getattr(args, field)
        if value is not None and not value.is_file():
            ap.error(f"--{field.replace('_', '-')} must be a file")
    args.env_file = env_file
    args.semantic_hf_home = args.semantic_hf_home.expanduser().resolve()
    model_path = Path(args.semantic_model).expanduser()
    if model_path.exists():
        if not model_path.is_dir():
            ap.error("--semantic-model local path must be a directory")
        args.semantic_model = str(model_path.resolve())
    elif model_path.is_absolute() or args.semantic_model.startswith((".", "~")):
        ap.error(f"Local semantic model directory does not exist: {args.semantic_model}")

    chunks_path = out / f"{args.module}_chunks.json"
    specs_dir = out / f"specs_{args.module}"
    selected_files = None
    if args.rtl_file_list:
        selected_files = []
        for line in args.rtl_file_list.expanduser().read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            path = Path(line.strip()).expanduser()
            path = (path if path.is_absolute() else repo / path).resolve()
            if not path.is_file() or not path.is_relative_to(repo) or path.suffix.lower() not in {".v", ".sv"}:
                ap.error(f"Invalid selected RTL file: {path}")
            selected_files.append(str(path))
        if not selected_files:
            ap.error("--rtl-file-list contains no RTL files")
    py = sys.executable
    chunk = [py, "-m", "rtl_bug_agent.cli", "chunk", "--rtl-dir", str(rtl), "--out", str(chunks_path)]
    if selected_files:
        chunk += ["--rtl-files", *selected_files]
    if args.prefilter:
        chunk += ["--prefilter", "--env-file", str(env_file), "--provider", args.provider,
                  "--thinking", args.thinking, "--llm-timeout", str(args.timeout)]
    specs = [py, str(PROJECT_ROOT / "scripts/generate_all_specs.py"), "--chunks", str(chunks_path),
             "--out-dir", str(specs_dir), "--env-file", str(env_file), "--provider", args.provider,
             "--thinking", args.thinking, "--workers", str(args.workers), "--llm-timeout", str(args.timeout),
             "--max-tokens", str(args.spec_max_tokens)]
    phase2 = [py, str(PROJECT_ROOT / "scripts/run_phase2_e2e.py"), "--ip", args.module,
              "--out-root", str(out), "--specs-dir", str(specs_dir), "--env-file", str(env_file),
              "--provider", args.provider, "--thinking", args.thinking, "--workers", str(args.workers),
              "--llm-timeout", str(args.timeout), "--channel-b-max-tokens", str(args.channel_b_max_tokens),
              "--ref-max-tokens", str(args.ref_max_tokens), "--ref-workers", str(args.workers),
              "--semantic-model", args.semantic_model, "--semantic-hf-home", str(args.semantic_hf_home.expanduser().resolve()),
              "--semantic-cache-dir", str(out / ".semantic_ag_cache"), "--semantic-batch-size", str(args.semantic_batch_size)]
    if args.no_ref:
        phase2 += ["--no-ref-augment"]
    elif args.ref_ip_root:
        phase2 += ["--opentitan-ip-root", str(args.ref_ip_root.expanduser().resolve())]
    else:
        phase2 += ["--ref-fragment-index", str(args.ref_fragment_index.expanduser().resolve())]
    if args.online_download_model:
        phase2 += ["--semantic-online-download-model"]
    commands = [("chunk", chunk), ("specs", specs), ("candidates and references", phase2)]
    if args.phase3 != "skip":
        phase3 = [py, str(PROJECT_ROOT / "scripts/run_phase3.py"), "--repo-root", str(repo),
                  "--out-root", str(out), "--run-root", str(out / "phase3"), "--modules", args.module,
                  "--env-file", str(env_file), "--provider-env-prefix", args.phase3_provider or args.provider,
                  "--run-id", args.run_id, "--codex-bin", args.codex_bin, "--concurrency", str(args.concurrency),
                  "--shard-size", str(args.shard_size)]
        if args.phase3_model:
            phase3 += ["--model", args.phase3_model]
        if args.phase3_prompt:
            phase3 += ["--prompt", str(args.phase3_prompt.expanduser().resolve())]
        if args.ref_fragment_index:
            phase3 += ["--fragment-index", str(args.ref_fragment_index.expanduser().resolve())]
        if args.phase3 == "prepare":
            phase3 += ["--prepare-only"]
        commands.append(("source review", phase3))
    child_env = os.environ.copy()
    child_env["ENV_FILE"] = str(env_file)
    child_env["PYTHONDONTWRITEBYTECODE"] = "1"
    identity = run_identity(args, repo, rtl, selected_files, env_file)
    check_run_identity(out, identity, create=not args.dry_run)
    for label, command in commands:
        print(f"[{label}] {shlex.join(command)}", flush=True)
        if args.dry_run:
            continue
        subprocess.run(command, cwd=PROJECT_ROOT, env=child_env, check=True)
        if label == "specs":
            check_specs(chunks_path, specs_dir)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"CRBC stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
