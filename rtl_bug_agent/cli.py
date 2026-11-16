from __future__ import annotations

import argparse
import json
from pathlib import Path

from rtl_bug_agent.env import get_hf_home, get_provider_config, load_dotenv, make_client
from rtl_bug_agent.llm.client import LlmConfig, OpenAICompatibleClient
from rtl_bug_agent.rtl.chunker import chunk_sv_files
from rtl_bug_agent.rtl.io import get_chunk, read_chunks, write_chunks
from rtl_bug_agent.spec.extractor import generate_chunk_spec
from rtl_bug_agent.phase2.semantic_ag import (
    SemanticBatchConfig,
    SemanticAgConfig,
    build_pairing as build_semantic_pairing,
    summarise_pairing,
)
from rtl_bug_agent.phase2.signal_graph import build_signal_graph


def main() -> None:
    parser = argparse.ArgumentParser(prog="rtl_bug_agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_chunk = sub.add_parser("chunk", help="Chunk RTL files into semantic units")
    p_chunk.add_argument("--rtl-dir", required=True)
    p_chunk.add_argument(
        "--rtl-file-list",
        help="Optional newline-delimited RTL file list. When supplied, only these files are chunked.",
    )
    p_chunk.add_argument(
        "--rtl-files", nargs="+",
        help="Optional explicit RTL files. When supplied, only these files are chunked.",
    )
    p_chunk.add_argument("--out", required=True)
    p_chunk.add_argument("--prefilter", action="store_true",
                          help="Use LLM to skip structural template sections")
    p_chunk.add_argument("--env-file", default=None, help="Dotenv file (default: ENV_FILE or project .env)")
    p_chunk.add_argument(
        "--provider",
        default="CRBC_OPENAI",
        help="LLM provider prefix for --prefilter (default: CRBC_OPENAI)",
    )
    p_chunk.add_argument(
        "--thinking",
        default="high",
        help="Reasoning strength for --prefilter; use none to omit it",
    )
    p_chunk.add_argument(
        "--prefilter-max-tokens",
        type=int,
        default=4000,
        help="Maximum completion tokens per --prefilter call (default: 4000)",
    )
    p_chunk.add_argument(
        "--llm-timeout", type=int, default=90,
        help="HTTP timeout in seconds for --prefilter calls (default: 90)",
    )

    p_show = sub.add_parser("show", help="Show one chunk")
    p_show.add_argument("--chunks", required=True)
    p_show.add_argument("--chunk-id")
    p_show.add_argument("--index", type=int)

    p_spec = sub.add_parser("spec", help="Generate spec for one selected chunk")
    p_spec.add_argument("--chunks", required=True)
    p_spec.add_argument("--chunk-id", required=True)
    p_spec.add_argument("--out", required=True)
    p_spec.add_argument("--env", "--env-file", dest="env", default=None,
                        help="Dotenv file (default: ENV_FILE or project .env)")
    p_spec.add_argument("--provider", default="CRBC_OPENAI")

    p_sem = sub.add_parser("semantic-ag", help="Dry-run semantic A-G retrieval")
    p_sem.add_argument("--specs-dir", required=True)
    p_sem.add_argument("--out", required=True)
    p_sem.add_argument("--cache-dir", default="output/.semantic_ag_cache")
    p_sem.add_argument("--model", default="BAAI/bge-m3")
    p_sem.add_argument("--hf-home",
                       default=None,
                       help="Local HuggingFace cache for BGE-M3; used offline by default")
    p_sem.add_argument("--online-download-model", action="store_true",
                       help="Allow HuggingFace network access to download missing model files")
    p_sem.add_argument("--batch-size", type=int, default=16)
    p_sem.add_argument("--embeddings",
                       help="Optional precomputed .npz embeddings for offline dry-run")
    p_sem.add_argument("--semantic-batch-mode", choices=["single", "guarded"],
                       default="single")
    p_sem.add_argument("--semantic-max-queries-per-batch", type=int, default=5)
    p_sem.add_argument("--semantic-max-prompt-tokens", type=int, default=5500)
    p_sem.add_argument("--semantic-max-dense-fallback-uncertain", type=int, default=1)
    p_sem.add_argument("--semantic-min-shared-roots", type=int, default=1)
    p_sem.add_argument("--semantic-max-signal-roots", type=int, default=4)
    p_sem.add_argument("--out-root",
                       help="Optional root directory for semantic artifacts")

    args = parser.parse_args()
    if args.cmd == "chunk":
        client = None
        if args.prefilter:
            load_dotenv(args.env_file)
            thinking = None if str(args.thinking).lower() == "none" else args.thinking
            client = make_client(args.provider, thinking=thinking, timeout_s=args.llm_timeout)
            print(f"Pre-filter LLM enabled ({args.provider})")
        explicit_files = args.rtl_files
        if args.rtl_file_list:
            listed = Path(args.rtl_file_list).read_text(encoding="utf-8").splitlines()
            explicit_files = [line.strip() for line in listed if line.strip() and not line.lstrip().startswith("#")]
        chunks = chunk_sv_files(
            args.rtl_dir,
            client=client,
            prefilter_max_tokens=args.prefilter_max_tokens,
            rtl_files=explicit_files,
        )
        write_chunks(chunks, args.out)
        by_kind: dict[str, int] = {}
        for chunk in chunks:
            by_kind[chunk.kind] = by_kind.get(chunk.kind, 0) + 1
        print(f"wrote {len(chunks)} chunks to {args.out}")
        print(json.dumps(by_kind, ensure_ascii=False, indent=2))
        for idx, chunk in enumerate(chunks[:20]):
            print(f"{idx:03d} {chunk.chunk_id} {chunk.source_file}:{chunk.line_start}-{chunk.line_end}")
        if len(chunks) > 20:
            print(f"... {len(chunks) - 20} more chunks")
        return

    if args.cmd == "show":
        chunks = read_chunks(args.chunks)
        if args.chunk_id:
            chunk = get_chunk(chunks, args.chunk_id)
        elif args.index is not None:
            chunk = chunks[args.index]
        else:
            raise SystemExit("show requires --chunk-id or --index")
        print(json.dumps(chunk.to_dict(), ensure_ascii=False, indent=2))
        return

    if args.cmd == "spec":
        load_dotenv(args.env)
        api_key, base_url, model = get_provider_config(args.provider)
        chunks = read_chunks(args.chunks)
        chunk = get_chunk(chunks, args.chunk_id)
        client = OpenAICompatibleClient(LlmConfig(api_key=api_key, base_url=base_url, model=model))
        spec = generate_chunk_spec(chunk, client)
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"wrote spec for {chunk.chunk_id} to {args.out}")
        return

    if args.cmd == "semantic-ag":
        graph = build_signal_graph(args.specs_dir)
        cfg = SemanticAgConfig(
            model_name=args.model,
            hf_home=args.hf_home or get_hf_home(),
            offline=not args.online_download_model,
            batch_size=args.batch_size,
        )
        batch_cfg = SemanticBatchConfig(
            mode=args.semantic_batch_mode,
            max_queries=args.semantic_max_queries_per_batch,
            max_prompt_tokens=args.semantic_max_prompt_tokens,
            max_dense_fallback_uncertain=args.semantic_max_dense_fallback_uncertain,
            min_shared_roots=args.semantic_min_shared_roots,
            max_signal_roots=args.semantic_max_signal_roots,
        )
        pairing = build_semantic_pairing(
            graph,
            cache_dir=args.cache_dir,
            config=cfg,
            embeddings_path=args.embeddings,
        )
        summary = summarise_pairing(pairing, batch_cfg)
        out_path = Path(args.out)
        if args.out_root:
            out_path = Path(args.out_root) / out_path.name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(pairing, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        print(f"wrote semantic AG pairing to {args.out}")
        return

if __name__ == "__main__":
    main()
