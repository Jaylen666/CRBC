"""LLM reference-atom extraction (per-file extraction -> incremental merge -> raw dump).

`extract_refs(...)` is the entry point used by the pipeline (run_phase2_e2e);
the module also provides a CLI for rerunning one module on its own.

Flow:
    1. Resolve the input files for <ip> (module-specific handling is listed in
       SPECIAL_INPUTS).
    2. Call the LLM **once per file** (config/prompts/phase2/ref_extract.md) and
       validate the response immediately.
    3. Merge the per-file ref_atoms incrementally (ref_id carries a filename
       prefix, so they cannot collide).
    4. Write <ip>_ref_raw.json (downstream matching consumes the raw atoms
       directly; see ref_match.py).

No module-level deduplication is performed: merging atoms dilutes the
embedding vectors and hurts top-N retrieval, so downstream retrieval works on
the raw atoms.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from dataclasses import dataclass
from collections import Counter
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from rtl_bug_agent.env import get_opentitan_ip_root, make_client, load_dotenv

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------
OPENTITAN_IP_ROOT = get_opentitan_ip_root()          # parent directory of the <ip> directories
PROMPT_DIR = _REPO_ROOT / "config" / "prompts" / "phase2"
EXTRACT_PROMPT_PATH = PROMPT_DIR / "ref_extract.md"
DEFAULT_OUT_DIR = _REPO_ROOT / "output" / "ref_out"

# API: same provider configuration as the consistency analyzer.
API_PREFIX = "CRBC_OPENAI"
MAX_TOKENS = 30000
EXTRACT_RETRIES = 3        # retries on a parse failure (LLM output is nondeterministic)
CKPT_DIRNAME = ".ckpt"     # checkpoint directory name (inside out-dir)

# ---------------------------------------------------------------------------
# Module-specific input handling
# ---------------------------------------------------------------------------
# Documentation source override.  The default is doc/theory_of_operation.md.
PRIM_FAMILY_ALIAS = "prim"
SPECIAL_INPUTS: dict[str, dict] = {
    "prim":                   {"doc_glob": "doc/*.md"},   # one call per prim_*.md document
    "prim_generic":           {"alias": PRIM_FAMILY_ALIAS},
    "prim_xilinx":            {"alias": PRIM_FAMILY_ALIAS},
    "prim_xilinx_ultrascale": {"alias": PRIM_FAMILY_ALIAS},
    "tlul":                   {"doc_files": ["doc/TlulProtocolChecker.md"]},
    # Prefer split KMAC documents when available, falling back to the upstream
    # theory_of_operation.md below.
    "kmac":                   {"doc_glob": "doc/theory_of_operation_part*.md"},
}

_VALID_KINDS = {"specific", "general"}
MAX_FRAGMENT_BYTES = 12_000
FRAGMENT_SPLIT_TRIGGER_BYTES = 38_000


@dataclass(frozen=True)
class FragmentInput:
    """One extractable, provenance-preserving fragment from a materializer index."""

    unit_id: str
    label: str
    content: str
    content_sha256: str
    provenance: dict[str, Any]


# ---------------------------------------------------------------------------
# Input file resolution
# ---------------------------------------------------------------------------
def _collect_data_hjson(ip_dir: Path) -> list[Path]:
    """Return every data/*.hjson document for this module."""
    data_dir = ip_dir / "data"
    if not data_dir.is_dir():
        return []
    return sorted(data_dir.glob("*.hjson"))


def resolve_input_files(ip: str, ip_root: Path) -> list[Path]:
    """Resolve the input files for <ip> (with module-specific handling).

    Default rule: data/*.hjson + doc/theory_of_operation.md.
    Module-specific overrides are listed in SPECIAL_INPUTS.
    """
    spec = SPECIAL_INPUTS.get(ip)
    if spec and "alias" in spec:
        return resolve_input_files(spec["alias"], ip_root)

    ip_dir = ip_root / ip
    if not ip_dir.is_dir():
        raise FileNotFoundError(f"IP directory not found: {ip_dir}")

    files: list[Path] = _collect_data_hjson(ip_dir)

    if spec and "doc_glob" in spec:
        files.extend(sorted(ip_dir.glob(spec["doc_glob"])))
        if ip == "kmac" and not any(path.name.startswith("theory_of_operation_part") for path in files):
            toa = ip_dir / "doc" / "theory_of_operation.md"
            if toa.is_file():
                files.append(toa)
    elif spec and "doc_files" in spec:
        for rel in spec["doc_files"]:
            p = ip_dir / rel
            if p.exists():
                files.append(p)
            else:
                print(f"  [warn] requested doc file not found, skipping: {p}")
    else:
        toa = ip_dir / "doc" / "theory_of_operation.md"
        if toa.exists():
            files.append(toa)

    if not files:
        raise FileNotFoundError(
            f"{ip}: no usable input files found (data/*.hjson and doc are both empty)"
        )
    return files


def resolve_fragment_inputs(ip: str, fragment_index: Path) -> list[FragmentInput]:
    """Load verified primary fragments for one Caliptra IP from its fragment index."""
    try:
        index = json.loads(fragment_index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid fragment index: {fragment_index}") from exc
    if index.get("schema_version") != 1 or not isinstance(index.get("fragments"), list):
        raise ValueError(f"unsupported fragment index schema: {fragment_index}")

    root = Path(index.get("caliptra_root", "")).resolve()
    if not root.is_dir():
        raise ValueError(f"fragment index has invalid caliptra_root: {root}")

    units: list[tuple[int, FragmentInput]] = []
    seen: set[str] = set()
    for record in index["fragments"]:
        if not isinstance(record, dict) or record.get("ip") != ip:
            continue
        if record.get("classification") != "primary" or record.get("extractable") is not True:
            continue
        required = (
            "unit_id", "source_path", "source_sha256", "heading_path", "line_start",
            "line_end", "byte_start", "byte_end", "content_sha256", "generated_output",
            "output_byte_start", "output_byte_end",
        )
        if any(field not in record for field in required):
            raise ValueError(f"fragment index record lacks provenance fields for {ip}")
        source_path = (root / str(record["source_path"])).resolve()
        if root not in source_path.parents or not source_path.is_file():
            raise ValueError(f"fragment source is unavailable: {record['source_path']}")
        source = source_path.read_bytes()
        if hashlib.sha256(source).hexdigest() != record["source_sha256"]:
            raise ValueError(f"fragment source hash drift: {record['source_path']}")
        start, end = int(record["byte_start"]), int(record["byte_end"])
        content = source[start:end]
        if hashlib.sha256(content).hexdigest() != record["content_sha256"]:
            raise ValueError(f"fragment content hash drift: {record['unit_id']}")
        unit_id = str(record["unit_id"])
        if unit_id in seen:
            raise ValueError(f"duplicate fragment unit_id for {ip}: {unit_id}")
        seen.add(unit_id)
        provenance = {
            "unit_id": unit_id,
            "source_path": record["source_path"],
            "heading_path": record["heading_path"],
            "line_start": record["line_start"],
            "line_end": record["line_end"],
            "byte_start": start,
            "byte_end": end,
            "content_sha256": record["content_sha256"],
            "generated_output": record["generated_output"],
            "output_byte_start": record["output_byte_start"],
            "output_byte_end": record["output_byte_end"],
        }
        if len(content) <= FRAGMENT_SPLIT_TRIGGER_BYTES:
            label = f"{record['source_path']}:{record['line_start']}-{record['line_end']}"
            units.append((int(record["output_byte_start"]), FragmentInput(
                unit_id=unit_id,
                label=label,
                content=content.decode("utf-8", errors="replace"),
                content_sha256=record["content_sha256"],
                provenance=provenance,
            )))
            continue

        # Large normative tables can exceed gateway request limits. Split them
        # only on original UTF-8 line boundaries, keeping each part traceable.
        lines = content.splitlines(keepends=True)
        part_start = 0
        part_size = 0
        part_line_start = 0
        part_number = 1

        def append_part(part_end: int, line_end_index: int) -> None:
            nonlocal part_number
            part = content[part_start:part_end]
            part_sha256 = hashlib.sha256(part).hexdigest()
            part_unit_id = f"{unit_id}:part{part_number:02d}"
            part_provenance = dict(provenance)
            part_provenance.update({
                "unit_id": part_unit_id,
                "parent_unit_id": unit_id,
                "source_byte_start": start + part_start,
                "source_byte_end": start + part_end,
                "byte_start": start + part_start,
                "byte_end": start + part_end,
                "line_start": int(record["line_start"]) + part_line_start,
                "line_end": int(record["line_start"]) + line_end_index,
                "content_sha256": part_sha256,
                "output_byte_start": int(record["output_byte_start"]) + part_start,
                "output_byte_end": int(record["output_byte_start"]) + part_end,
            })
            label = (
                f"{record['source_path']}:{part_provenance['line_start']}"
                f"-{part_provenance['line_end']} (part {part_number})"
            )
            units.append((int(part_provenance["output_byte_start"]), FragmentInput(
                unit_id=part_unit_id,
                label=label,
                content=part.decode("utf-8", errors="replace"),
                content_sha256=part_sha256,
                provenance=part_provenance,
            )))
            part_number += 1

        offset = 0
        for line_index, line in enumerate(lines):
            if part_size and part_size + len(line) > MAX_FRAGMENT_BYTES:
                append_part(offset, line_index - 1)
                part_start = offset
                part_size = 0
                part_line_start = line_index
            offset += len(line)
            part_size += len(line)
        if part_size:
            append_part(offset, len(lines) - 1)
    return [unit for _, unit in sorted(units, key=lambda item: item[0])]


# ---------------------------------------------------------------------------
# LLM response parsing
# ---------------------------------------------------------------------------
def parse_llm_json(content: str) -> dict:
    """Tolerate a ```json fence, trailing text after the object, and a truncated object."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    if start != -1:
        try:
            obj, _end = json.JSONDecoder().raw_decode(text, start)
            return obj
        except json.JSONDecodeError:
            pass

    tail = text[-80:].replace("\n", "\\n")
    raise RuntimeError(
        f"LLM response is not parseable as JSON (length {len(content)}, tail: ...{tail!r}). "
        f"A truncated string or missing closing brace usually means MAX_TOKENS is too "
        f"small; current MAX_TOKENS={MAX_TOKENS}."
    )


# ---------------------------------------------------------------------------
# Extraction-time validation
# ---------------------------------------------------------------------------
def validate_extract(doc: dict, src_name: str) -> dict:
    """Structurally validate one file's extraction result and apply light fixes."""
    atoms = doc.get("ref_atoms")
    if not isinstance(atoms, list):
        raise ValueError(f"{src_name}: response has no ref_atoms array")

    problems: list[str] = []
    for i, a in enumerate(atoms):
        kind = a.get("ref_kind")
        if kind not in _VALID_KINDS:
            problems.append(f"atom[{i}] invalid ref_kind: {kind!r}")
        if kind == "specific":
            if not (a.get("kind_reason") or "").strip():
                problems.append(f"atom[{i}] specific atom has no kind_reason")
        else:
            a["kind_reason"] = None

    n = len(atoms)
    if doc.get("num_of_ref_atoms") != n:
        print(f"    [fix] {src_name} num_of_ref_atoms {doc.get('num_of_ref_atoms')} -> {n}")
        doc["num_of_ref_atoms"] = n

    if problems:
        print(f"    [warn] {src_name} failed validation:")
        for p in problems:
            print(f"           - {p}")
    return doc


def extract_one_file(
    f: Path, prompt: str, client, max_tokens: int = MAX_TOKENS
) -> dict:
    """Extract one file with a single LLM call; returns the validated result.

    A parse failure is retried EXTRACT_RETRIES times; if it still fails the file
    is **skipped** (empty atoms are returned).
    """
    try:
        text = f.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        print(f"  [warn] cannot read {f.name}: {exc}")
        return {"file_involved": [f.name], "num_of_ref_atoms": 0, "ref_atoms": [], "_extract_ok": False}

    user_payload = f"===== FILE: {f.name} =====\n{text}"
    last_err = None
    for attempt in range(1, EXTRACT_RETRIES + 2):
        try:
            content = client.chat(
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": user_payload},
                ],
                max_tokens=max_tokens,
            )
        except Exception as exc:
            print(f"  [warn] {f.name} LLM request failed after client retries: {str(exc)[:120]}")
            return {"file_involved": [f.name], "num_of_ref_atoms": 0, "ref_atoms": [], "_extract_ok": False}
        try:
            doc = parse_llm_json(content)
            result = validate_extract(doc, f.name)
            result["_extract_ok"] = True
            return result
        except (RuntimeError, ValueError) as exc:
            last_err = exc
            print(f"    [retry] {f.name} extraction attempt {attempt} failed: {str(exc)[:90]}")

    print(f"  [warn] {f.name} failed to parse {EXTRACT_RETRIES + 1} times; skipping. Last error: {last_err}")
    return {"file_involved": [f.name], "num_of_ref_atoms": 0, "ref_atoms": [], "_extract_ok": False}


def extract_one_fragment(
    unit: FragmentInput, prompt: str, client, max_tokens: int = MAX_TOKENS
) -> dict:
    """Extract atoms from one canonical Markdown fragment with host provenance."""
    heading = " > ".join(str(part) for part in unit.provenance["heading_path"])
    user_payload = (
        f"===== FILE: {unit.label} =====\n"
        f"===== HEADING: {heading} =====\n"
        f"{unit.content}"
    )
    last_err = None
    for attempt in range(1, EXTRACT_RETRIES + 2):
        try:
            content = client.chat(
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": user_payload},
                ],
                max_tokens=max_tokens,
            )
        except Exception as exc:
            print(f"  [warn] {unit.label} LLM request failed after client retries: {str(exc)[:120]}")
            return {"file_involved": [unit.label], "num_of_ref_atoms": 0, "ref_atoms": [], "_extract_ok": False}
        try:
            doc = parse_llm_json(content)
            result = validate_extract(doc, unit.label)
            result["_extract_ok"] = True
            return result
        except (RuntimeError, ValueError) as exc:
            last_err = exc
            print(f"    [retry] {unit.label} extraction attempt {attempt} failed: {str(exc)[:90]}")

    print(f"  [warn] {unit.label} failed to parse {EXTRACT_RETRIES + 1} times; skipping. Last error: {last_err}")
    return {"file_involved": [unit.label], "num_of_ref_atoms": 0, "ref_atoms": [], "_extract_ok": False}


# ---------------------------------------------------------------------------
# Checkpoints (per file)
# ---------------------------------------------------------------------------
def _sha16(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _ip_ckpt_dir(ip: str, ckpt_root: Path) -> Path:
    return ckpt_root / ip


def load_file_ckpt(f: Path, prompt_hash: str, ckpt_dir: Path) -> list[dict] | None:
    """Return the cached ref_atoms on a hit, else None (missing, source changed, prompt changed)."""
    p = ckpt_dir / f"{f.name}.json"
    if not p.exists():
        return None
    try:
        ck = json.loads(p.read_text(encoding="utf-8"))
        src_hash = _sha16(f.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    if ck.get("src_hash") != src_hash or ck.get("prompt_hash") != prompt_hash:
        return None
    atoms = ck.get("ref_atoms")
    return atoms if isinstance(atoms, list) else None


def save_file_ckpt(f: Path, atoms: list[dict], prompt_hash: str, ckpt_dir: Path) -> None:
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    src_hash = _sha16(f.read_text(encoding="utf-8", errors="replace"))
    (ckpt_dir / f"{f.name}.json").write_text(
        json.dumps(
            {"src_name": f.name, "src_hash": src_hash,
             "prompt_hash": prompt_hash, "ref_atoms": atoms},
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )


def extract_or_cached(
    f: Path,
    prompt: str,
    prompt_hash: str,
    client,
    ckpt_dir: Path,
    fresh: bool,
    max_tokens: int,
) -> tuple[list[dict], bool, bool]:
    """Extract one file: return the checkpoint cache on a hit, else call the LLM and cache on success."""
    if not fresh:
        cached = load_file_ckpt(f, prompt_hash, ckpt_dir)
        if cached is not None:
            return cached, True, True

    doc = extract_one_file(f, prompt, client, max_tokens=max_tokens)
    atoms = doc.get("ref_atoms", [])
    ok = bool(doc.get("_extract_ok", True))
    if ok:
        # An empty list still means a successful extraction and must be cached to
        # distinguish it from an API failure.
        save_file_ckpt(f, atoms, prompt_hash, ckpt_dir)
    return atoms, False, ok


def _fragment_ckpt_path(unit: FragmentInput, ckpt_dir: Path) -> Path:
    return ckpt_dir / f"fragment_{_sha16(unit.unit_id)}.json"


def load_fragment_ckpt(unit: FragmentInput, prompt_hash: str, ckpt_dir: Path) -> list[dict] | None:
    path = _fragment_ckpt_path(unit, ckpt_dir)
    if not path.exists():
        return None
    try:
        checkpoint = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if checkpoint.get("unit_id") != unit.unit_id:
        return None
    if checkpoint.get("content_sha256") != unit.content_sha256:
        return None
    if checkpoint.get("prompt_hash") != prompt_hash:
        return None
    atoms = checkpoint.get("ref_atoms")
    return atoms if isinstance(atoms, list) else None


def save_fragment_ckpt(unit: FragmentInput, atoms: list[dict], prompt_hash: str, ckpt_dir: Path) -> None:
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    _fragment_ckpt_path(unit, ckpt_dir).write_text(
        json.dumps(
            {
                "unit_id": unit.unit_id,
                "label": unit.label,
                "content_sha256": unit.content_sha256,
                "prompt_hash": prompt_hash,
                "ref_atoms": atoms,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def extract_fragment_or_cached(
    unit: FragmentInput,
    prompt: str,
    prompt_hash: str,
    client,
    ckpt_dir: Path,
    fresh: bool,
    max_tokens: int,
) -> tuple[list[dict], bool, bool]:
    if not fresh:
        cached = load_fragment_ckpt(unit, prompt_hash, ckpt_dir)
        if cached is not None:
            return cached, True, True
    doc = extract_one_fragment(unit, prompt, client, max_tokens=max_tokens)
    atoms = doc.get("ref_atoms", [])
    ok = bool(doc.get("_extract_ok", True))
    if ok:
        save_fragment_ckpt(unit, atoms, prompt_hash, ckpt_dir)
    return atoms, False, ok


# ---------------------------------------------------------------------------
# Main extraction flow (shared by the library entry point and the CLI)
# ---------------------------------------------------------------------------
def _kind_dist(atoms: list[dict]) -> dict:
    return dict(Counter(a.get("ref_kind") for a in atoms))


def extract_refs_from_fragment_index(
    ip: str,
    out_dir: Path,
    *,
    fragment_index: Path,
    ckpt_dir: Path | None = None,
    workers: int = 4,
    fresh: bool = False,
    client: Any = None,
    max_tokens: int = MAX_TOKENS,
) -> Path | None:
    """Extract Caliptra refs one canonical primary fragment at a time."""
    units = resolve_fragment_inputs(ip, fragment_index)
    if not units:
        print(f"[skip] {ip}: fragment index has no extractable primary reference fragments.")
        return None

    out_dir = Path(out_dir)
    ckpt_root = ckpt_dir if ckpt_dir is not None else out_dir / CKPT_DIRNAME
    ip_ckpt_dir = _ip_ckpt_dir(ip, ckpt_root)
    if fresh and ip_ckpt_dir.exists():
        shutil.rmtree(ip_ckpt_dir)
        print(f"[fresh] cleared checkpoint: {ip_ckpt_dir}")
    if not EXTRACT_PROMPT_PATH.exists():
        raise FileNotFoundError(f"extraction prompt not found: {EXTRACT_PROMPT_PATH}")
    prompt = EXTRACT_PROMPT_PATH.read_text(encoding="utf-8")
    prompt_hash = _sha16(prompt)
    if client is None:
        client = make_client(API_PREFIX)

    model_label = getattr(getattr(client, "config", None), "model", API_PREFIX)
    workers = max(1, min(workers, len(units)))
    print(f"=== {ip} Caliptra primary fragments ({len(units)}) ===")
    for unit in units:
        print(f"  {unit.label}")
    print(f"\n=== per-fragment extraction (model={model_label}, workers={workers}) ===")

    per_unit_atoms: list[list[dict]] = [[] for _ in units]
    per_unit_ok: list[bool] = [False for _ in units]

    def _run_one(index: int, unit: FragmentInput) -> tuple[int, list[dict], bool, bool]:
        atoms, cached, ok = extract_fragment_or_cached(
            unit, prompt, prompt_hash, client, ip_ckpt_dir, fresh, max_tokens
        )
        provenance = unit.provenance
        normalized: list[dict] = []
        unit_prefix = _sha16(unit.unit_id)
        for ordinal, atom in enumerate(atoms, start=1):
            item = dict(atom)
            item["ref_id"] = f"{ip}_{unit_prefix}_{ordinal:03d}"
            item["source_provenance"] = provenance
            normalized.append(item)
        return index, normalized, cached, ok

    if workers == 1:
        for index, unit in enumerate(units):
            _, atoms, cached, ok = _run_one(index, unit)
            per_unit_atoms[index] = atoms
            per_unit_ok[index] = ok
            tag = "[cache] " if cached else ""
            print(f"  [{index + 1}/{len(units)}] {tag}{unit.label} -> {len(atoms)} atoms  kinds={_kind_dist(atoms)}")
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_run_one, index, unit): index for index, unit in enumerate(units)}
            for done_count, future in enumerate(as_completed(futures), start=1):
                index = futures[future]
                try:
                    _, atoms, cached, ok = future.result()
                    per_unit_atoms[index] = atoms
                    per_unit_ok[index] = ok
                    tag = "[cache] " if cached else ""
                except Exception as exc:
                    print(f"  [warn] extraction thread failed for {units[index].label}, skipping: {exc}")
                    per_unit_ok[index] = False
                    tag = ""
                print(f"  [{done_count}/{len(units)}] {tag}{units[index].label} -> {len(per_unit_atoms[index])} atoms  kinds={_kind_dist(per_unit_atoms[index])}")

    all_atoms = [atom for atoms in per_unit_atoms for atom in atoms]
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / f"{ip}_ref_raw.json"
    raw_path.write_text(
        json.dumps(
            {
                "ip": ip,
                "source_mode": "caliptra_fragment_index",
                "fragment_index": str(fragment_index.resolve()),
                "file_involved": [unit.label for unit in units],
                "num_of_ref_atoms": len(all_atoms),
                "extraction_complete": all(per_unit_ok),
                "failed_inputs": [units[i].label for i, ok in enumerate(per_unit_ok) if not ok],
                "total_tokens": None,
                "ref_atoms": all_atoms,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"  wrote raw → {raw_path} ({len(all_atoms)} atoms)")
    return raw_path


def extract_refs(
    ip: str,
    out_dir: Path,
    *,
    ip_root: Path | None = None,
    fragment_index: Path | None = None,
    ckpt_dir: Path | None = None,
    workers: int = 4,
    fresh: bool = False,
    client: Any = None,
    max_tokens: int = MAX_TOKENS,
) -> Path | None:
    """Extract the ref atoms for <ip> and write <out_dir>/<ip>_ref_raw.json.

    Returns the raw file path.
    Idempotent: a per-file checkpoint hit skips the LLM call, and a content-hash
    change triggers re-extraction automatically.
    """
    if fragment_index is not None:
        return extract_refs_from_fragment_index(
            ip,
            out_dir,
            fragment_index=Path(fragment_index),
            ckpt_dir=ckpt_dir,
            workers=workers,
            fresh=fresh,
            client=client,
            max_tokens=max_tokens,
        )

    out_dir = Path(out_dir)
    ckpt_root = ckpt_dir if ckpt_dir is not None else out_dir / CKPT_DIRNAME
    ip_ckpt_dir = _ip_ckpt_dir(ip, ckpt_root)
    if fresh and ip_ckpt_dir.exists():
        shutil.rmtree(ip_ckpt_dir)
        print(f"[fresh] cleared checkpoint: {ip_ckpt_dir}")

    files = resolve_input_files(ip, Path(ip_root) if ip_root is not None else get_opentitan_ip_root())
    alias = SPECIAL_INPUTS.get(ip, {}).get("alias")
    print(f"=== {ip} input files ({len(files)})"
          + (f"  [alias reuse: {alias}]" if alias else "") + " ===")
    for f in files:
        print(f"  {f}")

    if not EXTRACT_PROMPT_PATH.exists():
        raise FileNotFoundError(f"extraction prompt not found: {EXTRACT_PROMPT_PATH}")
    extract_prompt = EXTRACT_PROMPT_PATH.read_text(encoding="utf-8")
    extract_prompt_hash = _sha16(extract_prompt)

    if client is None:
        client = make_client(API_PREFIX)

    # Show the model actually in use (client may be injected by the caller with
    # a different provider than the module default API_PREFIX).
    model_label = getattr(getattr(client, "config", None), "model", API_PREFIX)
    workers = max(1, min(workers, len(files)))
    print(f"\n=== per-file extraction (model={model_label}, one call per file, workers={workers}) ===")

    per_file_atoms: list[list[dict]] = [[] for _ in files]
    per_file_ok: list[bool] = [False for _ in files]

    def _run_one(i: int, f: Path) -> tuple[int, list[dict], bool, bool]:
        atoms, cached, ok = extract_or_cached(
            f, extract_prompt, extract_prompt_hash, client, ip_ckpt_dir, fresh, max_tokens
        )
        # Legacy OpenTitan file extraction has no fragment index.  Still attach
        # deterministic provenance so the Phase3 gate can trace every atom
        # back to the exact source document and line range.
        try:
            raw = f.read_bytes()
            text = raw.decode("utf-8", errors="replace")
            provenance = {
                "source_path": str(f),
                "line_start": 1,
                "line_end": max(1, len(text.splitlines())),
                "content_sha256": hashlib.sha256(raw).hexdigest(),
            }
            atoms = [dict(a, source_provenance=provenance) for a in atoms]
        except OSError:
            ok = False
        return i, atoms, cached, ok

    if workers <= 1:
        for i, f in enumerate(files):
            _, atoms, cached, ok = _run_one(i, f)
            per_file_atoms[i] = atoms
            per_file_ok[i] = ok
            tag = "[cache] " if cached else ""
            print(f"  [{i + 1}/{len(files)}] {tag}{f.name} "
                  f"-> {len(atoms)} atoms  kinds={_kind_dist(atoms)}")
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as pool:
            fut_to_idx = {pool.submit(_run_one, i, f): i for i, f in enumerate(files)}
            done_count = 0
            for fut in as_completed(fut_to_idx):
                i = fut_to_idx[fut]
                try:
                    _, atoms, cached, ok = fut.result()
                    per_file_atoms[i] = atoms
                    per_file_ok[i] = ok
                    tag = "[cache] " if cached else ""
                except Exception as exc:
                    print(f"  [warn] extraction thread failed for {files[i].name}, skipping: {exc}")
                    per_file_atoms[i] = []
                    per_file_ok[i] = False
                    tag = ""
                done_count += 1
                print(f"  [{done_count}/{len(files)}] {tag}{files[i].name} "
                      f"-> {len(per_file_atoms[i])} atoms  kinds={_kind_dist(per_file_atoms[i])}")

    all_atoms: list[dict] = []
    files_involved: list[str] = []
    for i, f in enumerate(files):
        all_atoms.extend(per_file_atoms[i])
        files_involved.append(f.name)

    print(f"\n  total: {len(all_atoms)} atoms (from {len(files_involved)} files)"
          f"  kinds={_kind_dist(all_atoms)}")

    out_dir.mkdir(parents=True, exist_ok=True)
    raw_doc = {
        "ip": ip,
        "file_involved": files_involved,
        "num_of_ref_atoms": len(all_atoms),
        "extraction_complete": all(per_file_ok),
        "failed_inputs": [files[i].name for i, ok in enumerate(per_file_ok) if not ok],
        "total_tokens": None,
        "ref_atoms": all_atoms,
    }
    raw_path = out_dir / f"{ip}_ref_raw.json"
    raw_path.write_text(json.dumps(raw_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  wrote raw → {raw_path}")
    return raw_path


def main() -> int:
    ap = argparse.ArgumentParser(description="LLM reference-atom extraction (per-file, raw dump)")
    ap.add_argument("ip", help="module name, e.g. an OpenTitan IP directory")
    ap.add_argument("--ip-root", type=Path, default=None,
                    help="parent directory of the IP directories (default: OPENTITAN_ROOT/hw/ip)")
    ap.add_argument("--env-file", "--env", dest="env_file", default=None,
                    help="Dotenv file (default: ENV_FILE or project .env)")
    ap.add_argument("--provider", default=API_PREFIX, help="LLM provider environment prefix")
    ap.add_argument(
        "--fragment-index",
        type=Path,
        default=None,
        help="fragment index; when set, extraction walks extractable primary fragments instead of --ip-root.",
    )
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR,
                    help=f"output directory (default: {DEFAULT_OUT_DIR})")
    ap.add_argument("--workers", type=int, default=4,
                    help="parallel workers for per-file extraction (default 4; 1 means serial)")
    ap.add_argument("--max-tokens", type=int, default=MAX_TOKENS,
                    help=f"max completion tokens per extraction call (default: {MAX_TOKENS})")
    ap.add_argument("--fresh", action="store_true",
                    help="ignore and clear this IP's checkpoint, then re-extract everything")
    ap.add_argument("--ckpt-dir", type=Path, default=None,
                    help=f"checkpoint root (default: <out-dir>/{CKPT_DIRNAME})")
    args = ap.parse_args()

    load_dotenv(args.env_file)
    client = make_client(args.provider)
    extract_refs(
        args.ip, args.out_dir,
        ip_root=args.ip_root, fragment_index=args.fragment_index, ckpt_dir=args.ckpt_dir,
        workers=args.workers, fresh=args.fresh, max_tokens=args.max_tokens,
        client=client,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
