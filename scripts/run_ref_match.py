#!/usr/bin/env python3
"""Run ref_match in batch: attach ref_clues to a module's findings and write
*_ref_matched.json.

Batch mode (module names discovered from the ref files):
    .venv/bin/python run_ref_match.py
    .venv/bin/python run_ref_match.py --ref-dir ref_out --findings-dir output --modules module_a module_b

Single-module mode (explicit paths):
    .venv/bin/python run_ref_match.py --ip <name> --refs <ref_raw.json> --findings <findings.json>

    Output goes to findings_<ip>_ref_matched.json beside the findings file
    unless --out is given.

Output format: {"findings": [...]}. Findings are preserved as-is; only the
ref_clues field is added or overwritten.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from rtl_bug_agent.phase2.ref_match import RefMatchConfig, match, load_atoms, load_findings

REF_OUT = PROJECT_ROOT / "output" / "ref_out"
FINDINGS_OUT = PROJECT_ROOT / "output"

cfg = RefMatchConfig()   # max_specific=4, max_general=2, floor=0.40


def run_one(ip: str, atoms_path: Path, findings_path: Path,
            out_path: Path | None = None) -> None:
    print(f"=== {ip} ===")
    if not atoms_path.exists():
        print(f"  [skip] ref file not found: {atoms_path}")
        return
    if not findings_path.exists():
        print(f"  [skip] findings file not found: {findings_path}")
        return

    atoms = load_atoms(str(atoms_path))
    findings = load_findings(str(findings_path))
    print(f"  refs={len(atoms)}  findings={len(findings)}")

    match(findings, atoms, config=cfg, verbose=True)

    n_spec = sum(any(c["layer"] == "specific" for c in f.get("ref_clues", [])) for f in findings)
    n_gen  = sum(any(c["layer"] == "general"  for c in f.get("ref_clues", [])) for f in findings)
    n_none = sum(not f.get("ref_clues") for f in findings)
    all_scores = [c["score"] for f in findings for c in f.get("ref_clues", [])]
    avg = sum(all_scores) / len(all_scores) if all_scores else 0.0
    print(f"  specific_layer={n_spec} general_layer={n_gen} empty={n_none}  avg_score={avg:.3f}")

    dest = out_path or findings_path.parent / f"findings_{ip}_ref_matched.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps({"findings": findings}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"  wrote → {dest}\n")


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="run ref_match in batch or single-module mode")
    ap.add_argument("--ip",       help="module name (required in single-module mode)")
    ap.add_argument("--refs",     help="path to ref_raw.json (required in single-module mode)")
    ap.add_argument("--findings", help="path to findings_*.json (required in single-module mode)")
    ap.add_argument("--out",      help="output path (single-module mode; defaults to the findings directory)")
    ap.add_argument("--ref-dir", type=Path, default=REF_OUT,
                    help="directory holding ref_raw.json files (batch mode)")
    ap.add_argument("--findings-dir", type=Path, default=FINDINGS_OUT,
                    help="directory holding findings_*.json files (batch mode)")
    ap.add_argument("--modules", nargs="+", help="module names (batch mode); discovered from ref filenames by default")
    args = ap.parse_args()

    # Single-module mode: all three path arguments are required together.
    if args.ip or args.refs or args.findings:
        missing = [n for n, v in [("--ip", args.ip), ("--refs", args.refs),
                                   ("--findings", args.findings)] if not v]
        if missing:
            ap.error(f"single-module mode needs --ip / --refs / --findings; missing: {' '.join(missing)}")
        run_one(args.ip,
                Path(args.refs), Path(args.findings),
                Path(args.out) if args.out else None)
        return 0

    # Batch mode.
    if args.out:
        ap.error("--out only applies to single-module mode")
    print(f"RefMatchConfig: {cfg}\n")
    modules = args.modules or sorted(
        path.name.removesuffix("_ref_raw.json")
        for path in args.ref_dir.glob("*_ref_raw.json")
    )
    for ip in modules:
        run_one(ip, args.ref_dir / f"{ip}_ref_raw.json",
                args.findings_dir / f"findings_{ip}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
