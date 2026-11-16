#!/usr/bin/env python3
"""CRBC main path: semantic AGU -> consistency analyzer -> ref matching -> optional Phase3.

The expensive consistency analyzer work is checkpointed per semantic query unit. Reference
extraction is checkpointed per source document. The standalone Phase 3 controller
can consume the persisted findings for source review.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rtl_bug_agent.env import get_hf_home, get_opentitan_ip_root, load_dotenv, make_client
from rtl_bug_agent.phase2.channel_b import run_channel_b_semantic
from rtl_bug_agent.phase2.fusion import fuse, print_summary
from rtl_bug_agent.phase2.phase3 import verify_top_findings
from rtl_bug_agent.phase2.ref_extract import extract_refs
from rtl_bug_agent.phase2 import ref_match
from rtl_bug_agent.phase2.semantic_ag import (
    SemanticAgConfig,
    SemanticBatchConfig,
    build_pairing as build_semantic_pairing,
    summarise_pairing,
    warmup_model,
)
from rtl_bug_agent.phase2.signal_graph import build_signal_graph
from rtl_bug_agent.phase2.trace import TraceSink


def _checkpoint_path(out_root: Path, ip: str) -> Path:
    return out_root / f".checkpoint_{ip}_B_semantic.json"


def _as_dict(finding):
    return finding.to_dict() if hasattr(finding, "to_dict") else finding


def _merge_phase3_results(findings: list[dict], verified: list[dict]) -> list[dict]:
    """Overlay verified top-N findings without discarding unverified findings."""
    by_id = {str(item.get("finding_id", "")): item for item in verified}
    return [by_id.get(str(item.get("finding_id", "")), item) for item in findings]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", required=True)
    parser.add_argument("--out-root", default="output")
    parser.add_argument("--specs-dir", default=None)
    parser.add_argument("--env-file", "--env", dest="env_file", default=None,
                        help="Dotenv file (default: ENV_FILE or project .env)")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--provider", default="CRBC_OPENAI")
    parser.add_argument("--thinking", default="high")
    parser.add_argument("--llm-timeout", type=int, default=90)
    parser.add_argument("--semantic-cache-dir", default="output/.semantic_ag_cache")
    parser.add_argument("--semantic-model", default="BAAI/bge-m3")
    parser.add_argument(
        "--semantic-hf-home",
        default=None,
        help="HuggingFace cache (default: HF_HOME or project .cache/huggingface)",
    )
    parser.add_argument("--semantic-online-download-model", action="store_true")
    parser.add_argument("--semantic-batch-size", type=int, default=16)
    parser.add_argument("--semantic-embeddings")
    parser.add_argument("--semantic-batch-mode", choices=["single", "guarded"], default="guarded")
    parser.add_argument("--semantic-max-queries-per-batch", type=int, default=5)
    parser.add_argument("--semantic-max-prompt-tokens", type=int, default=5500)
    parser.add_argument("--semantic-max-dense-fallback-uncertain", type=int, default=1)
    parser.add_argument("--semantic-min-shared-roots", type=int, default=1)
    parser.add_argument("--semantic-max-signal-roots", type=int, default=4)
    parser.add_argument("--channel-b-max-tokens", type=int, default=10000)
    parser.add_argument(
        "--channel-b-max-units",
        type=int,
        default=None,
        help="Optional cap on semantic consistency analyzer query units; useful for bounded probes.",
    )
    parser.add_argument("--no-ref-augment", action="store_true")
    parser.add_argument("--ref-out-dir", default=None)
    parser.add_argument(
        "--opentitan-ip-root",
        default=None,
        help="OpenTitan hw/ip directory (default: OPENTITAN_ROOT/hw/ip or project external/opentitan/hw/ip).",
    )
    parser.add_argument(
        "--ref-fragment-index",
        default=None,
        help="Caliptra fragment index; extracts only primary/extractable source fragments with provenance.",
    )
    parser.add_argument("--ref-workers", type=int, default=4)
    parser.add_argument("--ref-max-tokens", type=int, default=30000)
    parser.add_argument("--ref-fresh", action="store_true")
    parser.add_argument("--phase3-top-n", type=int, default=0)
    parser.add_argument(
        "--phase3-checkpoint",
        default=None,
        help="Optional Phase3 per-finding checkpoint JSON; defaults under --out-root.",
    )
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()

    if args.phase3_top_n < 0:
        raise SystemExit("--phase3-top-n must be non-negative")
    if args.channel_b_max_units is not None and args.channel_b_max_units <= 0:
        raise SystemExit("--channel-b-max-units must be positive when supplied")

    ip = args.ip
    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    specs_dir = args.specs_dir or str(out_root / f"specs_{ip}")
    out_path = out_root / f"findings_{ip}.json"
    trace_sink = TraceSink(out_root / f"trace_{ip}.jsonl") if args.trace else None
    batch_cfg = SemanticBatchConfig(
        mode=args.semantic_batch_mode,
        max_queries=args.semantic_max_queries_per_batch,
        max_prompt_tokens=args.semantic_max_prompt_tokens,
        max_dense_fallback_uncertain=args.semantic_max_dense_fallback_uncertain,
        min_shared_roots=args.semantic_min_shared_roots,
        max_signal_roots=args.semantic_max_signal_roots,
    )

    load_dotenv(args.env_file)
    args.semantic_hf_home = args.semantic_hf_home or get_hf_home()
    args.opentitan_ip_root = args.opentitan_ip_root or str(get_opentitan_ip_root())
    thinking = None if str(args.thinking).lower() == "none" else args.thinking
    client = make_client(args.provider, thinking=thinking, timeout_s=args.llm_timeout)
    started = time.monotonic()
    print(f"LLM provider: {args.provider} (model={client.config.model}, thinking={thinking})")

    # Record elapsed time and token counters at each substage boundary.
    # Consistency analyzer and reference extraction share the client, so snapshot its
    # counters to attribute usage to each substage.
    stage_seconds: dict[str, float] = {}
    stage_tokens: dict[str, dict[str, int]] = {}
    stage_started = started
    _TOKEN_FIELDS = (
        "call_count", "error_count", "total_input_tokens",
        "total_cached_input_tokens", "total_output_tokens", "total_tokens",
    )
    snapshot = {key: int(client.stats().get(key, 0) or 0) for key in _TOKEN_FIELDS}

    def mark_stage(name: str) -> None:
        nonlocal stage_started, snapshot
        now = time.monotonic()
        stage_seconds[name] = round(now - stage_started, 1)
        stage_started = now
        current = {key: int(client.stats().get(key, 0) or 0) for key in _TOKEN_FIELDS}
        stage_tokens[name] = {key: current[key] - snapshot[key] for key in _TOKEN_FIELDS}
        stage_tokens[name]["wall_seconds"] = stage_seconds[name]
        snapshot = current

    print("=" * 60)
    print(f"Pass 0: Signal Dependency Graph ({ip})")
    print("=" * 60)
    graph = build_signal_graph(specs_dir)
    print(graph.summary())
    security_signals = set(graph.get_security_signals())
    mark_stage("pass0_signal_graph")

    semantic_cfg = SemanticAgConfig(
        model_name=args.semantic_model,
        hf_home=args.semantic_hf_home,
        offline=not args.semantic_online_download_model,
        batch_size=args.semantic_batch_size,
    )
    # Initialize BGE before consistency analyzer creates its worker pool. The model stays
    # cached for ref matching, avoiding first CUDA initialization after many
    # worker threads already exist.
    if not args.no_ref_augment:
        print("  Semantic AG: warming up BGE-M3 model ...")
        warmup_model(semantic_cfg)
        print("  Semantic AG: BGE-M3 warmup complete")
    print("  Semantic AG: building BGE-M3 pairing ...")
    pairing = build_semantic_pairing(
        graph,
        cache_dir=args.semantic_cache_dir,
        config=semantic_cfg,
        embeddings_path=args.semantic_embeddings,
    )
    pairing_summary = summarise_pairing(pairing, batch_cfg)
    shadow_path = out_root / f"semantic_ag_shadow_{ip}.json"
    shadow_path.write_text(json.dumps(pairing_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  Semantic AG summary written to {shadow_path}")
    mark_stage("semantic_ag")

    print("\n" + "=" * 60)
    print("Layer 1: consistency analyzer semantic A-G pairing")
    print("=" * 60)
    findings_b = run_channel_b_semantic(
        pairing,
        graph,
        client,
        workers=args.workers,
        max_tokens=args.channel_b_max_tokens,
        max_units=args.channel_b_max_units,
        checkpoint_path=str(_checkpoint_path(out_root, ip)),
        batch_config=batch_cfg,
        trace_sink=trace_sink,
    )

    merged = fuse({"B-AG": findings_b}, security_signals, trace_sink=trace_sink, cluster=False)
    print_summary(merged)
    mark_stage("channel_b_and_fuse")

    if not args.no_ref_augment:
        ref_out_dir = Path(args.ref_out_dir) if args.ref_out_dir else out_root / "ref_out"
        raw_path = ref_out_dir / f"{ip}_ref_raw.json"
        # Ref extraction is file-checkpointed.  A raw file may exist even when
        # one or more files failed (for example after an API timeout), so do not
        # treat mere existence as completion.  Retry incomplete extraction up
        # to three rounds; successful file checkpoints are reused and only
        # failed files call the API again.
        ref_complete = False
        for ref_attempt in range(1, 4):
            need_extract = args.ref_fresh or not raw_path.exists()
            if raw_path.exists() and not args.ref_fresh:
                try:
                    prior = json.loads(raw_path.read_text(encoding="utf-8"))
                    need_extract = not bool(prior.get("extraction_complete", False))
                except (OSError, json.JSONDecodeError):
                    need_extract = True
            if need_extract:
                print("\n" + "=" * 60)
                print(f"Ref extraction: {ip} (attempt {ref_attempt}/3)")
                print("=" * 60)
                raw_path = extract_refs(
                    ip,
                    ref_out_dir,
                    ip_root=Path(args.opentitan_ip_root),
                    fragment_index=Path(args.ref_fragment_index) if args.ref_fragment_index else None,
                    workers=args.ref_workers,
                    # --ref-fresh applies only to the first requested round;
                    # retries must preserve successful checkpoints.
                    fresh=args.ref_fresh and ref_attempt == 1,
                    client=client,
                    max_tokens=args.ref_max_tokens,
                )
            if raw_path is None or not Path(raw_path).exists():
                continue
            try:
                ref_doc = json.loads(Path(raw_path).read_text(encoding="utf-8"))
                ref_complete = bool(ref_doc.get("extraction_complete", False))
            except (OSError, json.JSONDecodeError):
                ref_complete = False
            if ref_complete:
                break
            try:
                failed = ref_doc.get("failed_inputs", [])
            except UnboundLocalError:
                failed = []
            print(f"  Ref extraction incomplete after attempt {ref_attempt}: failed={failed}")
        if not ref_complete:
            raise SystemExit(
                f"STOP: reference extraction incomplete after 3 attempts; "
                f"see {raw_path} (failed_inputs)"
            )
        mark_stage("ref_extraction")
        if raw_path is not None and Path(raw_path).exists():
            atoms = ref_match.load_atoms(str(raw_path))
            merged_dicts = [_as_dict(finding) for finding in merged]
            ref_match.match(merged_dicts, atoms, sem_config=semantic_cfg, verbose=True)
            merged = merged_dicts
            mark_stage("ref_matching")

    merged_dicts = [_as_dict(finding) for finding in merged]
    if args.phase3_top_n:
        print("\n" + "=" * 60)
        print(f"Phase 3: source-level verification (top {args.phase3_top_n})")
        print("=" * 60)
        verified = verify_top_findings(
            merged_dicts,
            graph,
            client,
            top_n=args.phase3_top_n,
            trace_sink=trace_sink,
            checkpoint_path=args.phase3_checkpoint or out_root / f".checkpoint_{ip}_phase3.json",
        )
        merged_dicts = _merge_phase3_results(merged_dicts, verified)
        mark_stage("phase3_verify")

    elapsed = time.monotonic() - started
    stage_seconds["unaccounted"] = round(max(elapsed - sum(stage_seconds.values()), 0.0), 1)
    stats = client.stats()
    stats["stage_seconds"] = dict(stage_seconds)
    stats["stage_tokens"] = dict(stage_tokens)
    # total_wall_seconds from the client is the sum of time spent in all LLM
    # workers/calls; retain it separately from this process's wall-clock time.
    worker_seconds = float(stats.get("total_wall_seconds", 0.0))
    stats["worker_wall_seconds"] = round(worker_seconds, 1)
    stats["script_wall_seconds"] = round(elapsed, 1)
    stats["parallelism_factor"] = round(worker_seconds / elapsed, 3) if elapsed > 0 else 0.0
    stats["total_wall_seconds"] = round(elapsed, 1)
    stats["total_wall_minutes"] = round(elapsed / 60, 1)
    output = {
        "_stats": stats,
        "_ag_pairing_mode": "semantic",
        "_semantic_batch_mode": args.semantic_batch_mode,
        "findings": merged_dicts,
    }
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {out_path}")
    client.print_stats()


if __name__ == "__main__":
    main()
