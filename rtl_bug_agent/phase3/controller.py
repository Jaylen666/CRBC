#!/usr/bin/env python3
"""Resumable CRBC Phase 3 source-review controller.

The controller owns selection, immutable shards, process supervision, validation,
checkpointing, retries, and reporting. Workers run read-only and only emit attempt
artifacts; they never modify findings or final result sidecars.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import re
import signal
import statistics
import subprocess
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo


VERDICTS = {"CONFIRMED", "FALSE_ALARM", "NEEDS_MORE_CONTEXT", "UNCERTAIN"}
REF_CLASSES = {
    "same_behavior", "overlapping", "adjacent", "contradictory", "unrelated",
    "not_actionable",
}
# Models are supplied explicitly or through the configured provider.
MODEL = ""
REASONING_EFFORT = "medium"
WORKER_VIEW_VERSION = "crbc_phase3_worker_view.v1"
SHARD_SIZE = 40
DEFAULT_CONCURRENCY = 3
MAX_CONCURRENCY = 50

_ATTEMPT_RE = re.compile(r"^(shard_\d+)(?:_(F-\d+))?_attempt_(\d+)$")


def classify_attempt(name: str) -> tuple[str | None, bool, int]:
    """Split an attempt directory name into (base_shard, is_finding_retry, n).

    Two retry shapes exist and the previous classifier only recognised the first:

        shard_001_attempt_02          -> shard retry, attempt number 2
        shard_001_F-0052_attempt_01   -> finding-level retry, attempt number 1

    A finding-level retry re-runs work that the parent shard already covered, so
    it is a retry even though its attempt number is 1.  Counting only
    attempt_number > 1 silently reports retry time as useful time.
    """
    match = _ATTEMPT_RE.match(str(name))
    if not match:
        return None, False, 0
    base, finding_id, attempt_no = match.groups()
    return base, finding_id is not None, int(attempt_no)
STALL_SECONDS = 30 * 60
ATTEMPT_SECONDS = 120 * 60
INTERRUPT_GRACE_SECONDS = 2 * 60
SHANGHAI = ZoneInfo("Asia/Shanghai")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def local_time(value: str | None) -> str | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(SHANGHAI).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        .encode("utf-8")
    )


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def dotenv_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def selected_findings(
    findings: Iterable[dict[str, Any]],
    forced_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Apply the fixed union predicate, stable ordering, and ID deduplication."""
    selected = []
    forced_ids = forced_ids or set()
    seen: set[str] = set()
    ordered = sorted(
        findings,
        key=lambda finding: (
            -float(finding.get("score", 0.0) or 0.0),
            str(finding.get("finding_id", "")),
        ),
    )
    for finding in ordered:
        finding_id = str(finding.get("finding_id", ""))
        severity = str(finding.get("severity", "")).upper()
        if (
            finding_id not in forced_ids
            and severity != "HIGH"
            and not (finding.get("ref_clues") or [])
        ):
            continue
        if not finding_id or finding_id in seen:
            continue
        seen.add(finding_id)
        selected.append(finding)
    return selected


def finding_for_worker(finding: dict[str, Any], finding_hash: str) -> dict[str, Any]:
    """Remove prior verification/formal artifacts while preserving Phase2 evidence and refs."""
    forbidden = {
        "formal", "formal_verdict", "formal_confidence", "formal_draft",
        "formalization", "phase3", "phase3_verdict", "trace_ref",
    }
    return {
        **{key: value for key, value in finding.items() if key not in forbidden},
        "finding_hash": finding_hash,
    }


def chunks(values: list[Any], size: int = SHARD_SIZE) -> list[list[Any]]:
    if size < 1:
        raise ValueError("shard size must be positive")
    return [values[index:index + size] for index in range(0, len(values), size)]


def load_ref_ids(path: Path) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return set(), [f"cannot read raw ref JSON: {exc}"]
    atoms = document.get("ref_atoms") if isinstance(document, dict) else None
    if not isinstance(atoms, list):
        return set(), ["raw ref document has no ref_atoms array"]
    ids: set[str] = set()
    for index, atom in enumerate(atoms):
        if not isinstance(atom, dict):
            errors.append(f"atom {index} is not an object")
            continue
        ref_id = atom.get("ref_id")
        if not isinstance(ref_id, str) or not ref_id:
            errors.append(f"atom {index} has invalid ref_id")
        elif ref_id in ids:
            errors.append(f"duplicate ref_id {ref_id}")
        else:
            ids.add(ref_id)
        if atom.get("ref_kind") not in {"specific", "general"}:
            errors.append(f"atom {index} has invalid ref_kind {atom.get('ref_kind')!r}")
        provenance = atom.get("source_provenance")
        if not isinstance(provenance, dict):
            errors.append(f"atom {index} has no source_provenance")
        else:
            for key in ("source_path", "line_start", "line_end", "content_sha256"):
                if key not in provenance:
                    errors.append(f"atom {index} provenance missing {key}")
    return ids, errors


def ref_fragment_modules(fragment_index: Path) -> set[str]:
    document = json.loads(fragment_index.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for fragment in document.get("fragments", []):
        if fragment.get("extractable") is not True or fragment.get("classification") != "primary":
            continue
        modules.update(str(ip) for ip in fragment.get("scope_ips", []))
    return modules


def resolve_evidence_path(raw: str, rtl_root: Path) -> Path | None:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = rtl_root / candidate
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(rtl_root.resolve())
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def excerpt_matches(path: Path, line: int, excerpt: str) -> bool:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    if line < 1 or line > len(lines):
        return False
    expected = re.sub(r"\s+", " ", lines[line - 1].strip())
    actual = re.sub(r"\s+", " ", excerpt.strip())
    return bool(actual) and (actual in expected or expected in actual)


def load_worker_document(text: str) -> Any:
    """Parse a worker output document, tolerating prose or a fence around it.

    A worker may prefix the JSON with a sentence ("I have enough evidence.
    Writing the verification results.") and then emit a complete, valid
    document.  A plain json.loads() fails at character 0 on those and would
    discard the whole shard, so fall back to raw_decode, which finds the first
    complete JSON value and ignores whatever surrounds it.

    strict=False additionally tolerates a literal control character inside a
    JSON string, such as an evidence excerpt that carries a raw newline
    instead of ``\n``.  The flag only relaxes that one rule; the document still
    has to be structurally valid JSON.

    This changes only how the text is read.  Every result still goes through
    validate_result() unchanged, so nothing that was rejected for a substantive
    reason can pass because of this.
    """
    def acceptable(document: Any) -> bool:
        # The top-level container specifically, not merely *some* object -- and not
        # a bare list: a truncated document whose first result parses cleanly would
        # otherwise be handed to the caller as a list of one result entry.
        return isinstance(document, dict) and isinstance(document.get("results"), list)

    try:
        document = json.loads(text, strict=False)
    except json.JSONDecodeError:
        pass
    else:
        if acceptable(document):
            return document
    # Bounded: a pathological file should not turn this into a quadratic scan.
    decoder = json.JSONDecoder(strict=False)
    for index in [i for i, char in enumerate(text) if char == "{"][:64]:
        try:
            document, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        # Require the top-level container, not merely *some* object.  When the
        # document is malformed past its first result, raw_decode(text[0:])
        # fails and the next candidate is the first *result* object, which is
        # also a dict -- returning it yields a document with no "results" list
        # and the caller reports "output has no results array", mislabelling a
        # truncated document as a schema mistake.
        if acceptable(document):
            return document
    raise json.JSONDecodeError(
        "no JSON document with a results list found in worker output", text, 0)


def validate_result(
    result: Any,
    finding: dict[str, Any],
    finding_hash: str,
    rtl_root: Path,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(result, dict):
        return ["result is not an object"]
    required = {
        "finding_id", "finding_hash", "verdict", "confidence", "is_extra_finding",
        "extra_finding_from_ref", "matched_ref_ids", "ref_assessments", "summary",
        "root_cause", "trigger_condition", "security_impact", "software_visible",
        "reasoning", "source_evidence", "additional_findings",
    }
    missing = sorted(required - set(result))
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
    forbidden = {"formalization", "formal", "sva"} & set(result)
    if forbidden:
        errors.append(f"forbidden fields: {', '.join(sorted(forbidden))}")
    if result.get("finding_id") != finding.get("finding_id"):
        errors.append("finding_id mismatch")
    if result.get("finding_hash") != finding_hash:
        errors.append("finding_hash mismatch")
    verdict = result.get("verdict")
    if verdict not in VERDICTS:
        errors.append(f"invalid verdict {verdict!r}")
    confidence = result.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        errors.append("confidence must be in [0, 1]")
    for key in ("is_extra_finding", "software_visible"):
        if not isinstance(result.get(key), bool):
            errors.append(f"{key} must be boolean")
    supplied_ref_ids = [
        clue.get("ref_id") for clue in (finding.get("ref_clues") or [])
        if isinstance(clue, dict) and isinstance(clue.get("ref_id"), str)
    ]
    supplied_ref_set = set(supplied_ref_ids)
    matched = result.get("matched_ref_ids")
    if not isinstance(matched, list) or any(value not in supplied_ref_set for value in matched):
        errors.append("matched_ref_ids contains an unknown ref ID")
    assessments = result.get("ref_assessments")
    assessed_ids: list[str] = []
    if not isinstance(assessments, list):
        errors.append("ref_assessments must be an array")
    else:
        for assessment in assessments:
            if not isinstance(assessment, dict):
                errors.append("ref assessment is not an object")
                continue
            ref_id = assessment.get("ref_id")
            assessed_ids.append(ref_id)
            if assessment.get("classification") not in REF_CLASSES:
                errors.append(f"invalid ref classification for {ref_id!r}")
            if not str(assessment.get("assessment", "")).strip():
                errors.append(f"empty ref assessment for {ref_id!r}")
        if Counter(assessed_ids) != Counter(supplied_ref_ids):
            errors.append("ref_assessments does not exactly cover supplied ref clues")
    extra_ref = result.get("extra_finding_from_ref")
    if extra_ref is not None and extra_ref not in supplied_ref_set:
        errors.append("extra_finding_from_ref is not a supplied ref ID")
    if extra_ref is not None and result.get("is_extra_finding") is not True:
        errors.append("extra_finding_from_ref requires is_extra_finding=true")
    for key in ("summary", "reasoning"):
        if not str(result.get(key, "")).strip():
            errors.append(f"{key} must be nonempty")
    if verdict == "CONFIRMED":
        for key in ("root_cause", "trigger_condition", "security_impact"):
            if not str(result.get(key, "")).strip():
                errors.append(f"CONFIRMED requires {key}")
    if verdict == "NEEDS_MORE_CONTEXT":
        joined = f"{result.get('summary', '')} {result.get('reasoning', '')}".lower()
        if not any(word in joined for word in ("missing", "need", "requires", "lack", "unclear")):
            errors.append("NEEDS_MORE_CONTEXT must identify missing context")
    evidence = result.get("source_evidence")
    if not isinstance(evidence, list):
        errors.append("source_evidence must be an array")
    else:
        if verdict in {"CONFIRMED", "FALSE_ALARM"} and not evidence:
            errors.append(f"{verdict} requires source_evidence")
        for item in evidence:
            if not isinstance(item, dict):
                errors.append("source evidence is not an object")
                continue
            path = resolve_evidence_path(str(item.get("path", "")), rtl_root)
            line = item.get("line")
            excerpt = item.get("excerpt")
            if path is None:
                errors.append(f"evidence path is outside or absent: {item.get('path')!r}")
            elif isinstance(line, bool) or not isinstance(line, int) or line < 1:
                errors.append(f"invalid evidence line for {item.get('path')!r}")
            elif not isinstance(excerpt, str) or not excerpt_matches(path, line, excerpt):
                errors.append(f"evidence excerpt mismatch at {item.get('path')}:{line}")
    if not isinstance(result.get("additional_findings"), list):
        errors.append("additional_findings must be an array")
    return errors


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(percentile_value * len(ordered)) - 1)
    return ordered[index]


@dataclass
class WorkItem:
    ip: str
    shard_id: str
    finding_ids: list[str]
    retry_depth: int = 0
    focused: bool = False


@dataclass
class AttemptOutcome:
    valid_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    invalid: dict[str, list[str]] = field(default_factory=dict)
    retry_reason: str | None = None
    timing: dict[str, Any] = field(default_factory=dict)


class Controller:
    def __init__(self, args: argparse.Namespace) -> None:
        self.repo_root = Path(args.repo_root).resolve()
        self.out_root = Path(args.out_root).resolve()
        self.run_root = Path(args.run_root).resolve()
        self.prompt_path = Path(args.prompt).resolve()
        self.schema_path = Path(args.schema).resolve()
        self.fragment_index = Path(args.fragment_index).resolve() if args.fragment_index else None
        self.run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.run_dir = self.run_root / "phase3_runs" / self.run_id
        self.worker_home = self.run_dir / "worker_home"
        self.worker_codex_home = self.worker_home / ".codex"
        self.trace_path = self.run_dir / "trace.jsonl"
        self.codex_bin = args.codex_bin
        self.concurrency = args.concurrency
        self.shard_size = args.shard_size
        self.forced_finding_ids = {str(item) for item in (args.force_finding or []) if str(item)}
        self.stall_seconds = args.stall_seconds
        self.attempt_seconds = args.attempt_seconds
        self.interrupt_grace_seconds = args.interrupt_grace_seconds
        self.prepare_only = args.prepare_only
        self.pilot_only = args.pilot_only
        self.allow_provider_model_mismatch = args.allow_provider_model_mismatch
        self.selected_file_map = Path(args.selected_file_map).resolve() if args.selected_file_map else None
        if args.modules:
            self.modules = [item.strip() for item in args.modules.split(",") if item.strip()]
        elif self.selected_file_map and self.selected_file_map.is_file():
            try:
                mapping = json.loads(self.selected_file_map.read_text(encoding="utf-8"))
                self.modules = list(mapping.get("modules", {}).keys())
            except (OSError, json.JSONDecodeError):
                self.modules = sorted(
                    path.stem.removeprefix("findings_")
                    for path in self.out_root.glob("findings_*.json")
                )
        else:
            self.modules = sorted(
                path.stem.removeprefix("findings_")
                for path in self.out_root.glob("findings_*.json")
            )
        self.selected_rtl_files: set[str] = set()
        if self.selected_file_map and self.selected_file_map.is_file():
            try:
                mapping = json.loads(self.selected_file_map.read_text(encoding="utf-8"))
                for module in self.modules:
                    self.selected_rtl_files.update(
                        str(path) for path in mapping.get("modules", {}).get(module, {}).get("strict_selected_files", [])
                    )
            except (OSError, json.JSONDecodeError):
                pass
        all_env_values = dotenv_values(Path(args.env_file))
        all_env_values.update(os.environ)
        self.provider_prefix = args.provider_env_prefix
        provider_values = {
            f"{self.provider_prefix}_{suffix}": all_env_values[f"{self.provider_prefix}_{suffix}"]
            for suffix in ("API_KEY", "BASE_URL", "MODEL")
            if f"{self.provider_prefix}_{suffix}" in all_env_values
        }
        self.provider_key_name = f"{self.provider_prefix}_API_KEY"
        self.provider_base_url = provider_values.get(f"{self.provider_prefix}_BASE_URL", "")
        self.provider_model = provider_values.get(f"{self.provider_prefix}_MODEL", "")
        # Requested Codex model: an explicit --model (or $CRBC_PHASE3_MODEL) wins,
        # otherwise follow the provider's own MODEL so switching providers only
        # requires --provider-env-prefix.
        self.model = args.model or all_env_values.get("CRBC_PHASE3_MODEL") or self.provider_model or MODEL
        self.child_env = os.environ.copy()
        self.child_env.update(provider_values)
        self.child_env["HOME"] = str(self.worker_home)
        self.child_env["CODEX_HOME"] = str(self.worker_codex_home)
        self.child_env["XDG_CONFIG_HOME"] = str(self.worker_home / ".config")
        self.child_env["XDG_CACHE_HOME"] = str(self.worker_home / ".cache")
        self.child_env["XDG_DATA_HOME"] = str(self.worker_home / ".local" / "share")
        self.worker_skills_dir = self.worker_codex_home / "skills"
        self.audit_roots = sorted({
            str(path.parent) for path in (self.repo_root, self.out_root, self.run_root)
            if path.parent != Path(path.anchor)
        })
        self.findings: dict[str, dict[str, dict[str, Any]]] = {}
        self.finding_hashes: dict[str, dict[str, str]] = {}
        self.shards: dict[tuple[str, str], list[str]] = {}
        self.checkpoints: dict[str, dict[str, Any]] = {}
        self.manifest: dict[str, Any] = {}
        self.codex_version = ""
        self.active_process_groups: set[int] = set()
        self._run_started_mono = time.monotonic()

    def trace(self, event: str, **fields: Any) -> None:
        append_jsonl(self.trace_path, {"at": utc_now(), "event": event, **fields})

    def preflight(self) -> None:
        for path, label in (
            (self.repo_root, "repository root"),
            (self.out_root, "Phase 2 output root"),
            (self.prompt_path, "Phase3 prompt"),
            (self.schema_path, "Phase3 schema"),
        ):
            if not path.exists():
                raise SystemExit(f"Missing {label}: {path}")
        if self.fragment_index and not self.fragment_index.is_file():
            raise SystemExit(f"Missing ref fragment index: {self.fragment_index}")
        if not self.modules:
            raise SystemExit("No findings_<module>.json files found; provide --modules and Phase 2 outputs")
        if self.selected_file_map and not self.selected_file_map.is_file():
            raise SystemExit(f"Missing selected RTL map: {self.selected_file_map}")
        if self.selected_file_map and not self.selected_rtl_files:
            raise SystemExit("Selected RTL map contains no files for the requested modules")
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.worker_codex_home.mkdir(parents=True, exist_ok=True)
        if self.prepare_only:
            return
        if not self.model:
            raise SystemExit(f"Set --model, CRBC_PHASE3_MODEL, or {self.provider_prefix}_MODEL")
        if not self.provider_base_url.startswith(("http://", "https://")):
            raise SystemExit(f"{self.provider_prefix}_BASE_URL is missing or invalid")
        if not self.child_env.get(self.provider_key_name):
            raise SystemExit(f"{self.provider_key_name} is missing")
        if self.provider_model and self.provider_model != self.model and not self.allow_provider_model_mismatch:
            raise SystemExit(
                f"{self.provider_prefix}_MODEL={self.provider_model!r} does not match required model "
                f"{self.model!r} (set --model to match, or --allow-provider-model-mismatch to override)"
            )
        completed = subprocess.run(
            [self.codex_bin, "--version"], text=True, capture_output=True, check=False,
        )
        if completed.returncode != 0:
            raise SystemExit(f"Cannot execute Codex CLI: {completed.stderr.strip()}")
        self.codex_version = completed.stdout.strip()

    def prepare(self) -> None:
        self.preflight()
        extractable = ref_fragment_modules(self.fragment_index) if self.fragment_index else set()
        ref_status: dict[str, Any] = {}
        module_manifest: dict[str, Any] = {}
        for ip in self.modules:
            findings_path = self.out_root / f"findings_{ip}.json"
            if not findings_path.is_file():
                raise SystemExit(f"Missing findings for {ip}: {findings_path}")
            document = json.loads(findings_path.read_text(encoding="utf-8"))
            all_findings = document.get("findings")
            if not isinstance(all_findings, list):
                raise SystemExit(f"Invalid findings document for {ip}")
            raw_ref_path = self.out_root / "ref_out" / f"{ip}_ref_raw.json"
            ref_ids: set[str] = set()
            ref_errors: list[str] = []
            if raw_ref_path.is_file():
                ref_ids, ref_errors = load_ref_ids(raw_ref_path)
                ref_status[ip] = {
                    "status": "complete" if not ref_errors else "invalid",
                    "path": str(raw_ref_path),
                    "sha256": sha256_file(raw_ref_path),
                    "ref_count": len(ref_ids),
                    "errors": ref_errors,
                }
            elif ip not in extractable:
                ref_status[ip] = {"status": "not_applicable", "reason": "no primary extractable fragment"}
            else:
                ref_status[ip] = {"status": "missing", "path": str(raw_ref_path)}
                ref_errors.append("extractable module is missing raw ref JSON")
            unknown_clues: list[str] = []
            for finding in all_findings:
                for clue in finding.get("ref_clues") or []:
                    ref_id = clue.get("ref_id") if isinstance(clue, dict) else None
                    if ref_id not in ref_ids:
                        unknown_clues.append(str(ref_id))
                    if not isinstance(clue, dict) or not isinstance(clue.get("source_provenance"), dict):
                        unknown_clues.append(f"{ref_id}:missing_provenance")
            if unknown_clues:
                ref_errors.append(f"finding clues not traceable to raw refs: {sorted(set(unknown_clues))[:20]}")
            if ref_errors:
                raise SystemExit(f"Ref validation failed for {ip}: {'; '.join(ref_errors)}")
            module_forced = {
                item.split("/", 1)[1] if item.startswith(f"{ip}/") else item
                for item in self.forced_finding_ids
                if "/" not in item or item.startswith(f"{ip}/")
            }
            selected = selected_findings(all_findings, module_forced)
            self.findings[ip] = {}
            self.finding_hashes[ip] = {}
            for finding in selected:
                finding_id = str(finding["finding_id"])
                digest = canonical_hash(finding)
                self.findings[ip][finding_id] = finding
                self.finding_hashes[ip][finding_id] = digest
            ip_shards = chunks(selected, self.shard_size)
            for index, shard_findings in enumerate(ip_shards, start=1):
                shard_id = f"shard_{index:03d}"
                ids = [str(finding["finding_id"]) for finding in shard_findings]
                self.shards[(ip, shard_id)] = ids
                shard_path = self.run_dir / ip / "inputs" / f"{shard_id}.json"
                payload = {
                    "schema_version": "crbc_phase3_input.v1",
                    "ip": ip,
                    "shard_id": shard_id,
                    "rtl_root": str(self.repo_root),
                    "findings": [
                        finding_for_worker(self.findings[ip][finding_id], self.finding_hashes[ip][finding_id])
                        for finding_id in ids
                    ],
                }
                if shard_path.exists() and sha256_file(shard_path) != sha256_bytes(
                    (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                ):
                    raise SystemExit(f"Refusing to overwrite drifted frozen shard: {shard_path}")
                atomic_json(shard_path, payload)
            module_manifest[ip] = {
                "findings_path": str(findings_path),
                "findings_sha256": sha256_file(findings_path),
                "total_findings": len(all_findings),
                "selected_findings": len(selected),
                "shard_count": len(ip_shards),
                "ref": ref_status[ip],
                "status": "pending" if selected else "complete",
            }
        if self.selected_rtl_files:
            rtl_files = sorted(
                self.repo_root / relative for relative in self.selected_rtl_files
                if (self.repo_root / relative).is_file()
            )
        else:
            rtl_files = sorted(
                path for path in self.repo_root.rglob("*")
                if path.is_file() and path.suffix.lower() in {".sv", ".svh", ".v", ".vh"}
            )
        fingerprints = {
            str(path.relative_to(self.repo_root)): sha256_file(path) for path in rtl_files
        }
        existing = self._load_manifest()
        frozen = {
            "prompt_sha256": sha256_file(self.prompt_path),
            "schema_sha256": sha256_file(self.schema_path),
            "fragment_index_sha256": sha256_file(self.fragment_index) if self.fragment_index else None,
            "worker_view_version": WORKER_VIEW_VERSION,
            "model": self.model,
            "rtl_files": fingerprints,
        }
        if existing and existing.get("frozen") != frozen:
            raise SystemExit("Frozen prompt/schema/fragment-index/RTL inputs drifted; use a new run ID")
        self.manifest = existing or {
            "schema_version": "crbc_phase3_manifest.v1",
            "run_id": self.run_id,
            "created_at": utc_now(),
            "model": self.model,
            "reasoning_effort": REASONING_EFFORT,
            "worker_codex_home": str(self.worker_codex_home),
            "codex_version": self.codex_version,
            "command_template": self.command_template(),
            "selection": "severity == HIGH OR ref_clues nonempty",
            "module_order": self.modules,
            "shard_size": self.shard_size,
            "max_concurrency": self.concurrency,
            "frozen": frozen,
            "modules": module_manifest,
            "status": "prepared",
        }
        self.manifest["command_template"] = self.command_template()
        self.manifest["model"] = self.model
        self.manifest["codex_version"] = self.codex_version
        self.manifest["max_concurrency"] = self.concurrency
        atomic_json(self.run_dir / "manifest.json", self.manifest)
        self._load_checkpoints()
        self.trace("prepared", selected=sum(len(values) for values in self.findings.values()))

    def _load_manifest(self) -> dict[str, Any]:
        path = self.run_dir / "manifest.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}

    def command_template(self) -> list[str]:
        escaped_base_url = self.provider_base_url.replace("\\", "\\\\").replace('"', '\\"')
        return [
            self.codex_bin, "exec", "--model", self.model,
            "-c", f'model_reasoning_effort="{REASONING_EFFORT}"',
            "-c", 'model_provider="Phase3Provider"',
            "-c", 'model_providers.Phase3Provider.name="openai-compatible"',
            "-c", f'model_providers.Phase3Provider.base_url="{escaped_base_url}"',
            "-c", f'model_providers.Phase3Provider.env_key="{self.provider_key_name}"',
            "-c", 'model_providers.Phase3Provider.wire_api="responses"',
            "-c", "model_providers.Phase3Provider.requires_openai_auth=false",
            "-c", 'shell_environment_policy.inherit="core"',
            "--disable", "plugins",
            "--strict-config", "--ignore-user-config", "--ephemeral",
            "--sandbox", "read-only", "--skip-git-repo-check", "--json",
            "--output-schema", str(self.schema_path),
            "--output-last-message", "<attempt-output>", "-C", str(self.repo_root), "-",
        ]

    def _load_checkpoints(self) -> None:
        for ip in self.modules:
            path = self.run_dir / ip / "checkpoint.json"
            if path.is_file():
                checkpoint = json.loads(path.read_text(encoding="utf-8"))
            else:
                checkpoint = {"schema_version": "crbc_phase3_checkpoint.v1", "results": {}}
            valid: dict[str, Any] = {}
            for finding_id, entry in checkpoint.get("results", {}).items():
                finding = self.findings[ip].get(finding_id)
                if finding is None:
                    continue
                errors = validate_result(
                    entry.get("result"), finding, self.finding_hashes[ip][finding_id], self.repo_root,
                )
                if not errors:
                    valid[finding_id] = entry
            checkpoint["results"] = valid
            self.checkpoints[ip] = checkpoint
            atomic_json(path, checkpoint)

    def check_drift(self) -> list[str]:
        errors: list[str] = []
        frozen = self.manifest["frozen"]
        for path, expected in (
            (self.prompt_path, frozen["prompt_sha256"]),
            (self.schema_path, frozen["schema_sha256"]),
            (self.fragment_index, frozen["fragment_index_sha256"]),
        ):
            if path is not None and sha256_file(path) != expected:
                errors.append(str(path))
        for relative, expected in frozen["rtl_files"].items():
            path = self.repo_root / relative
            if not path.is_file() or sha256_file(path) != expected:
                errors.append(str(path))
        for ip, module in self.manifest["modules"].items():
            path = Path(module["findings_path"])
            if sha256_file(path) != module["findings_sha256"]:
                errors.append(str(path))
            ref = module["ref"]
            if ref.get("status") == "complete" and sha256_file(Path(ref["path"])) != ref["sha256"]:
                errors.append(ref["path"])
        return errors

    def completed_ids(self, ip: str) -> set[str]:
        return set(self.checkpoints[ip]["results"])

    def checkpoint_result(self, ip: str, result: dict[str, Any], attempt: str) -> None:
        finding_id = result["finding_id"]
        self.checkpoints[ip]["results"][finding_id] = {
            "finding_hash": self.finding_hashes[ip][finding_id],
            "validated_at": utc_now(),
            "attempt": attempt,
            "result": result,
        }
        atomic_json(self.run_dir / ip / "checkpoint.json", self.checkpoints[ip])

    def next_attempt_number(self, ip: str, shard_id: str) -> int:
        attempts_dir = self.run_dir / ip / "attempts"
        pattern = f"{shard_id}_attempt_*"
        return len(list(attempts_dir.glob(pattern))) + 1 if attempts_dir.exists() else 1

    def make_attempt_input(self, item: WorkItem, attempt_dir: Path) -> Path:
        path = attempt_dir / "input.json"
        atomic_json(path, {
            "schema_version": "crbc_phase3_input.v1",
            "ip": item.ip,
            "shard_id": item.shard_id,
            "focused": item.focused,
            "rtl_root": str(self.repo_root),
            "findings": [
                finding_for_worker(
                    self.findings[item.ip][finding_id], self.finding_hashes[item.ip][finding_id]
                )
                for finding_id in item.finding_ids
            ],
        })
        return path

    # ---- audit scoping helpers (used by audit_events) -------------------------------
    # `codex exec` runs its shell commands through /bin/bash -lc '<body>'; unwrap that so
    # the verb scan below sees the pipeline the worker actually wrote.
    _SHELL_WRAP = re.compile(r"\s*(?:/bin/)?(?:bash|sh)\s+-lc\s+(['\"])(.*)\1\s*$", re.S)
    # Verbs that only move NAMES around.  Applied to a directory they can only ever see a
    # name list, never file contents, so they cannot ground a verdict.
    _NAME_ONLY_VERBS = frozenset({
        "find", "ls", "tree", "du", "stat", "cd", "sort", "uniq", "wc", "cut", "tr",
        "head", "tail", "echo", "true", "false", "printf", "basename", "dirname",
        "realpath", "readlink", "pwd",
        # `rg --files` is ripgrep's name-lister (the equivalent of `find -type f`).  It is
        # folded into this single token before the verb scan; bare `rg` is NOT allowlisted.
        "rg_files",
    })
    # Anything that can pull file CONTENTS through a directory path -- i.e. recurse.
    # `head`/`sort`/`wc` are deliberately absent: they are stream shapers, and pointed at
    # a directory they only ever see a name list.  `rg` is a reader unless it is
    # `rg --files`, which enumerates.
    _CONTENT_THROUGH_DIR = re.compile(
        r"-exec\b|-delete\b|\bxargs\b|\btar\b|\brsync\b|\bcat\b|\bsed\b|\bnl\b|\bgrep\b"
        r"|\bawk\b|\bpython3?\b|\bperl\b|\bdiff\b|\bcp\b|\bmv\b|\bstrings\b|\bxxd\b"
        r"|\bod\b|\bag\b|\back\b|\brg\b(?!\s+--files)"
    )

    def _is_ancestor_enumeration(self, command: str, normalized: str, workspace: Path) -> bool:
        """True when `normalized` merely CONTAINS the workspace and the command only lists.

        The audit matches absolute paths that appear in a command string, so a plain
        prefix test cannot tell "read a neighbouring artifact" from "which directory am
        I in?".  The controller hands the worker an absolute path into its own attempt
        directory, so an agent that orients itself necessarily names that directory's
        ancestors, and `..` is never empty.

        The exemption therefore keys on semantics and needs BOTH halves:
          * the path strictly CONTAINS the workspace (it is an ancestor directory), and
          * every command in the pipeline is a name-only verb, with no content reader
            anywhere in the string.
        Anything UNDER an ancestor -- a sibling attempt's `output.json`, a checkpoint, a
        results file -- is not the ancestor itself, so it stays a violation, as does any
        content read from any ancestor.
        """
        if not str(workspace).startswith(normalized + "/"):
            return False
        if self._CONTENT_THROUGH_DIR.search(command):
            return False
        body = command
        wrap = self._SHELL_WRAP.match(body)
        if wrap:
            body = wrap.group(2)
        # Fold `rg --files` into one token so the verb scan sees a single allowlisted verb.
        body = re.sub(r"\brg\s+--files\b", "rg_files", body)
        verbs = [p.split()[0].rsplit("/", 1)[-1]
                 for p in re.split(r"\|\||&&|[;|]", body) if p.split()]
        return bool(verbs) and all(verb in self._NAME_ONLY_VERBS for verb in verbs)

    def audit_events(self, path: Path, allowed_input: Path, workspace: Path) -> list[str]:
        """Return paths the worker touched outside its permitted read scope.

        Every absolute path in a `command_execution` event is compared against the
        controller's audit roots.  Paths that do not exist cannot supply evidence and
        are ignored.
        """
        violations: list[str] = []
        if not path.is_file():
            return violations
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = event.get("item") if isinstance(event, dict) else None
            if not isinstance(item, dict) or item.get("type") != "command_execution":
                continue
            command = str(item.get("command", ""))
            for absolute in re.findall(r"/[A-Za-z0-9_][A-Za-z0-9_./-]*", command):
                # Collapse ".."/"." before the prefix tests: a raw string prefix check
                # would accept "<root>/../elsewhere/..." (escapes the audit roots) and
                # "<attempt_dir>/../<other shard>/..." (escapes into a sibling shard).
                normalized = os.path.normpath(absolute.rstrip("/.,:;\"'"))
                if not any(normalized == root or normalized.startswith(root + "/")
                           for root in self.audit_roots):
                    continue
                # A path that does not exist cannot supply evidence, so it is not a read.
                # Speculative probes of a misspelled repository should not void a shard
                # when no file contents could have been read.
                if not os.path.exists(normalized):
                    continue
                # The worker's own attempt directory is in scope: the controller hands it
                # the absolute input.json path in the task text, so an agent that works by
                # cd-ing into its workspace only ever touches files the controller itself
                # wrote there.  Nothing in that directory is an outside evidence source --
                # it holds one input.json and the worker's own output -- so reading it
                # cannot ground a verdict in the wrong RTL, which is what this audit is for.
                # Deliberately NOT widened to the whole run directory: sibling attempts and
                # other shards' results stay forbidden.
                if (
                    normalized == str(allowed_input)
                    or normalized == str(workspace)
                    or normalized.startswith(str(workspace) + "/")
                    or self._is_ancestor_enumeration(command, normalized, workspace)
                    or normalized == str(self.worker_skills_dir)
                    or normalized.startswith(str(self.worker_skills_dir) + "/")
                    or normalized == str(self.repo_root)
                    or normalized.startswith(str(self.repo_root) + "/")
                ):
                    continue
                violations.append(normalized)
        return sorted(set(violations))

    async def run_attempt(self, item: WorkItem) -> AttemptOutcome:
        drift = self.check_drift()
        if drift:
            self.trace("input_drift", paths=drift)
            raise RuntimeError(f"Input drift detected: {drift[:5]}")
        attempt_number = self.next_attempt_number(item.ip, item.shard_id)
        attempt_name = f"{item.shard_id}_attempt_{attempt_number:02d}"
        attempt_dir = self.run_dir / item.ip / "attempts" / attempt_name
        attempt_dir.mkdir(parents=True, exist_ok=False)
        input_path = self.make_attempt_input(item, attempt_dir)
        output_path = attempt_dir / "output.json"
        events_path = attempt_dir / "events.jsonl"
        stderr_path = attempt_dir / "stderr.log"
        prompt = self.prompt_path.read_text(encoding="utf-8")
        task = f"{prompt}\n\nThe only shard input you may read is: {input_path}\n"
        command = self.command_template()
        command[command.index("<attempt-output>")] = str(output_path)
        timing: dict[str, Any] = {
            "attempt": attempt_name,
            "launch_requested_at": utc_now(),
            "started_at": None,
            "first_output_at": None,
            "last_output_at": None,
            "process_exit_at": None,
            "validation_finished_at": None,
            "closed_at": None,
            "wall_seconds": 0.0,
            "exit_status": None,
            "retry_reason": None,
            "command": command,
            "codex_version": self.codex_version,
            "requested_model": self.model,
            "reasoning_effort": REASONING_EFFORT,
            "finding_ids": item.finding_ids,
        }
        atomic_json(attempt_dir / "metadata.json", timing)
        started_mono = time.monotonic()
        timing["started_at"] = utc_now()
        self.trace("attempt_started", ip=item.ip, shard=item.shard_id, attempt=attempt_name,
                   finding_ids=item.finding_ids)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            env=self.child_env,
            limit=32 * 1024 * 1024,
        )
        self.active_process_groups.add(process.pid)
        assert process.stdin and process.stdout and process.stderr
        process.stdin.write(task.encode("utf-8"))
        await process.stdin.drain()
        process.stdin.close()
        activity_mono = time.monotonic()

        async def capture(stream: asyncio.StreamReader, path: Path, jsonl: bool) -> None:
            nonlocal activity_mono
            with path.open("ab") as handle:
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    handle.write(line)
                    handle.flush()
                    activity_mono = time.monotonic()
                    now = utc_now()
                    timing["last_output_at"] = now
                    if timing["first_output_at"] is None:
                        timing["first_output_at"] = now
                    if jsonl:
                        try:
                            event = json.loads(line)
                            self.trace("agent_event", ip=item.ip, shard=item.shard_id,
                                       attempt=attempt_name, agent_event=event.get("type"))
                        except json.JSONDecodeError:
                            pass

        stdout_task = asyncio.create_task(capture(process.stdout, events_path, True))
        stderr_task = asyncio.create_task(capture(process.stderr, stderr_path, False))
        retry_reason: str | None = None
        while process.returncode is None:
            elapsed = time.monotonic() - started_mono
            idle = time.monotonic() - activity_mono
            if elapsed >= self.attempt_seconds:
                retry_reason = "attempt_timeout"
            elif idle >= self.stall_seconds:
                retry_reason = "stalled"
            if retry_reason:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), timeout=self.interrupt_grace_seconds)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        await asyncio.wait_for(process.wait(), timeout=10)
                    except asyncio.TimeoutError:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await process.wait()
                break
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                continue
        await asyncio.gather(stdout_task, stderr_task)
        process_group_reaped = True
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        else:
            process_group_reaped = False
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                process_group_reaped = True
            if not process_group_reaped:
                for _ in range(20):
                    await asyncio.sleep(0.25)
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        process_group_reaped = True
                        break
            if not process_group_reaped:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    process_group_reaped = True
                else:
                    await asyncio.sleep(0.1)
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        process_group_reaped = True
        timing["process_exit_at"] = utc_now()
        timing["exit_status"] = process.returncode
        timing["process_group_reaped"] = process_group_reaped
        self.active_process_groups.discard(process.pid)
        outcome = AttemptOutcome(timing=timing)
        expected = set(item.finding_ids)
        if retry_reason:
            outcome.retry_reason = retry_reason
        elif process.returncode != 0:
            outcome.retry_reason = "codex_exit_nonzero"
        elif not process_group_reaped:
            outcome.retry_reason = "lingering_process_group"
        elif self.audit_events(events_path, input_path, attempt_dir):
            outcome.retry_reason = "forbidden_input_access"
        else:
            try:
                document = load_worker_document(output_path.read_text(encoding="utf-8"))
                results = document.get("results") if isinstance(document, dict) else None
                if not isinstance(results, list):
                    raise ValueError("output has no results array")
                counts = Counter(result.get("finding_id") for result in results if isinstance(result, dict))
                for finding_id in expected:
                    candidates = [
                        result for result in results
                        if isinstance(result, dict) and result.get("finding_id") == finding_id
                    ]
                    if counts[finding_id] != 1:
                        outcome.invalid[finding_id] = [f"expected one result, got {counts[finding_id]}"]
                        continue
                    errors = validate_result(
                        candidates[0], self.findings[item.ip][finding_id],
                        self.finding_hashes[item.ip][finding_id], self.repo_root,
                    )
                    if errors:
                        outcome.invalid[finding_id] = errors
                    else:
                        outcome.valid_results[finding_id] = candidates[0]
                extras = set(counts) - expected
                if extras:
                    outcome.retry_reason = f"unexpected_finding_ids:{sorted(extras)}"
                    for finding_id in expected:
                        outcome.invalid.setdefault(finding_id, []).append("attempt included unexpected IDs")
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                outcome.retry_reason = f"invalid_json:{exc}"
        if outcome.retry_reason:
            for finding_id in expected - set(outcome.valid_results):
                outcome.invalid.setdefault(finding_id, []).append(outcome.retry_reason)
        for result in outcome.valid_results.values():
            self.checkpoint_result(item.ip, result, attempt_name)
        timing["validation_finished_at"] = utc_now()
        timing["retry_reason"] = outcome.retry_reason or (
            "validation_error" if outcome.invalid else None
        )
        timing["closed_at"] = utc_now()
        timing["wall_seconds"] = round(time.monotonic() - started_mono, 3)
        atomic_json(attempt_dir / "metadata.json", timing)
        atomic_json(attempt_dir / "validation.json", {
            "valid_ids": sorted(outcome.valid_results),
            "invalid": outcome.invalid,
            "retry_reason": outcome.retry_reason,
        })
        self.trace("attempt_closed", ip=item.ip, shard=item.shard_id, attempt=attempt_name,
                   valid_ids=sorted(outcome.valid_results), invalid=outcome.invalid,
                   retry_reason=outcome.retry_reason, wall_seconds=timing["wall_seconds"])
        return outcome

    def reap_active_process_groups(self) -> None:
        for process_group in list(self.active_process_groups):
            try:
                os.killpg(process_group, signal.SIGINT)
            except ProcessLookupError:
                self.active_process_groups.discard(process_group)
        if self.active_process_groups:
            time.sleep(2)
        for process_group in list(self.active_process_groups):
            try:
                os.killpg(process_group, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.active_process_groups.discard(process_group)

    def recover_stale_attempts(self) -> None:
        for path in self.run_dir.glob("*/attempts/*/metadata.json"):
            try:
                metadata = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if metadata.get("closed_at"):
                continue
            now = utc_now()
            metadata.update({
                "process_exit_at": metadata.get("process_exit_at") or now,
                "validation_finished_at": metadata.get("validation_finished_at") or now,
                "closed_at": now,
                "exit_status": metadata.get("exit_status") if metadata.get("exit_status") is not None else 130,
                "retry_reason": metadata.get("retry_reason") or "controller_interrupted",
                "process_group_reaped": True,
            })
            atomic_json(path, metadata)
            self.trace("stale_attempt_recovered", metadata_path=str(path))

    def initial_queue(self) -> deque[WorkItem]:
        queue: deque[WorkItem] = deque()
        for ip in self.modules:
            for (candidate_ip, shard_id), ids in self.shards.items():
                if candidate_ip != ip:
                    continue
                missing = [finding_id for finding_id in ids if finding_id not in self.completed_ids(ip)]
                if missing:
                    queue.append(WorkItem(ip, shard_id, missing))
        return queue

    async def run_queue(self, queue: deque[WorkItem], pilot: bool = False) -> None:
        active: dict[asyncio.Task[AttemptOutcome], WorkItem] = {}
        failures: Counter[tuple[str, str]] = Counter()
        while queue or active:
            while queue and len(active) < (1 if pilot else self.concurrency):
                item = queue.popleft()
                missing = [fid for fid in item.finding_ids if fid not in self.completed_ids(item.ip)]
                if not missing:
                    continue
                item.finding_ids = missing
                task = asyncio.create_task(self.run_attempt(item))
                active[task] = item
            if not active:
                continue
            done, _ = await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                item = active.pop(task)
                outcome = task.result()
                missing = [fid for fid in item.finding_ids if fid not in self.completed_ids(item.ip)]
                if missing:
                    key = (item.ip, item.shard_id)
                    failures[key] += 1
                    if failures[key] <= 3 and len(missing) > 1:
                        queue.append(WorkItem(item.ip, item.shard_id, missing,
                                              retry_depth=item.retry_depth + 1))
                    elif item.focused:
                        queue.append(WorkItem(
                            item.ip, item.shard_id, missing,
                            retry_depth=item.retry_depth + 1, focused=True,
                        ))
                    else:
                        for finding_id in missing:
                            queue.append(WorkItem(
                                item.ip, f"{item.shard_id}_{finding_id}", [finding_id],
                                retry_depth=item.retry_depth + 1, focused=True,
                            ))
                if pilot and not queue and not active:
                    return

    async def execute(self) -> None:
        self.prepare()
        self.recover_stale_attempts()
        if self.prepare_only:
            self.write_reports(final=False)
            return
        # Run the first shard as a cheap pilot before opening the rest of the
        # queue, so a misconfigured provider or endpoint fails on one shard
        # instead of across the whole run.  A resumed run whose first shard is
        # already complete skips straight to the full queue.
        queue = self.initial_queue()
        pilot_ids: list[str] = []
        if queue:
            pilot_ids = self.shards.get((queue[0].ip, queue[0].shard_id), [])
        pilot_complete = bool(pilot_ids) and all(
            finding_id in self.completed_ids(queue[0].ip) for finding_id in pilot_ids
        )
        if queue and not pilot_complete:
            first = queue.popleft()
            self.manifest["status"] = "pilot_running"
            atomic_json(self.run_dir / "manifest.json", self.manifest)
            await self.run_queue(deque([first]), pilot=True)
            remaining = set(first.finding_ids) - self.completed_ids(first.ip)
            if remaining:
                raise RuntimeError(f"pilot shard did not validate: {sorted(remaining)}")
            self.trace("pilot_complete", finding_count=len(first.finding_ids))
            self.write_reports(final=False)
            if self.pilot_only:
                return
            queue = self.initial_queue()
        elif pilot_complete:
            self.trace("pilot_already_complete", finding_count=len(pilot_ids))
            if self.pilot_only:
                self.write_reports(final=False)
                return
        self.manifest["status"] = "running"
        atomic_json(self.run_dir / "manifest.json", self.manifest)
        await self.run_queue(queue)
        missing = {
            ip: sorted(set(self.findings[ip]) - self.completed_ids(ip))
            for ip in self.modules if set(self.findings[ip]) - self.completed_ids(ip)
        }
        if missing:
            raise RuntimeError(f"Phase3 incomplete: {missing}")
        self.write_reports(final=True)

    def attempt_metadata(self) -> list[dict[str, Any]]:
        metadata = []
        for path in self.run_dir.glob("*/attempts/*/metadata.json"):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                usage = {"input_tokens": 0, "cached_input_tokens": 0, "output_tokens": 0, "reasoning_output_tokens": 0}
                events_path = path.parent / "events.jsonl"
                if events_path.is_file():
                    for line in events_path.read_text(encoding="utf-8", errors="replace").splitlines():
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if event.get("type") != "turn.completed" or not isinstance(event.get("usage"), dict):
                            continue
                        for key in usage:
                            usage[key] += int(event["usage"].get(key, 0) or 0)
                usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
                item.update({f"llm_{key}": value for key, value in usage.items()})
                metadata.append(item)
            except (OSError, json.JSONDecodeError):
                continue
        return metadata

    def write_reports(self, final: bool) -> None:
        attempts = self.attempt_metadata()
        shard_records: list[dict[str, Any]] = []
        module_records: dict[str, Any] = {}
        for ip in self.modules:
            results = [entry["result"] for entry in self.checkpoints[ip]["results"].values()]
            results.sort(key=lambda result: result["finding_id"])
            atomic_json(self.run_dir / ip / "phase3_results.json", {
                "schema_version": "crbc_phase3_results.v1", "ip": ip, "results": results,
            })
            ip_attempts = [entry for entry in attempts if str(entry.get("attempt", "")).startswith("shard_")
                           and (self.run_dir / ip / "attempts" / str(entry.get("attempt"))).exists()]
            for (candidate_ip, shard_id), ids in self.shards.items():
                if candidate_ip != ip:
                    continue
                related = [entry for entry in ip_attempts if str(entry.get("attempt", "")).startswith(shard_id)]
                starts = [entry["started_at"] for entry in related if entry.get("started_at")]
                closes = [entry["closed_at"] for entry in related if entry.get("closed_at")]
                complete = all(fid in self.completed_ids(ip) for fid in ids)
                wall = 0.0
                if starts and closes:
                    wall = (
                        datetime.fromisoformat(max(closes).replace("Z", "+00:00")) -
                        datetime.fromisoformat(min(starts).replace("Z", "+00:00"))
                    ).total_seconds()
                verdict_counts = Counter(
                    self.checkpoints[ip]["results"][fid]["result"]["verdict"]
                    for fid in ids if fid in self.completed_ids(ip)
                )
                shard_records.append({
                    "ip": ip, "shard_id": shard_id,
                    "started_at": min(starts) if starts else None,
                    "started_at_shanghai": local_time(min(starts)) if starts else None,
                    "completed_at": max(closes) if complete and closes else None,
                    "completed_at_shanghai": local_time(max(closes)) if complete and closes else None,
                    "wall_seconds": round(wall, 3),
                    "active_agent_seconds": round(sum(float(entry.get("wall_seconds", 0)) for entry in related), 3),
                    "attempt_count": len(related),
                    "retry_count": max(0, len(related) - 1),
                    "finding_count": len(ids),
                    "verdict_counts": dict(verdict_counts),
                    "status": "complete" if complete else "pending",
                })
            selected_count = len(self.findings[ip])
            complete_count = len(self.completed_ids(ip))
            active_seconds = sum(float(entry.get("wall_seconds", 0)) for entry in ip_attempts)
            module_records[ip] = {
                "status": "complete" if complete_count == selected_count else "pending",
                "finding_count": selected_count,
                "completed_findings": complete_count,
                "attempt_count": len(ip_attempts),
                "active_agent_seconds": round(active_seconds, 3),
                "finding_per_hour": round(complete_count * 3600 / active_seconds, 3) if active_seconds else 0.0,
                "verdict_counts": dict(Counter(result["verdict"] for result in results)),
            }
        durations = [record["wall_seconds"] for record in shard_records if record["status"] == "complete"]
        active_seconds = sum(float(entry.get("wall_seconds", 0)) for entry in attempts)
        run_wall = max(time.monotonic() - self._run_started_mono, 0.001)
        llm_input_tokens = sum(int(entry.get("llm_input_tokens", 0) or 0) for entry in attempts)
        llm_cached_input_tokens = sum(int(entry.get("llm_cached_input_tokens", 0) or 0) for entry in attempts)
        llm_output_tokens = sum(int(entry.get("llm_output_tokens", 0) or 0) for entry in attempts)
        llm_reasoning_tokens = sum(int(entry.get("llm_reasoning_output_tokens", 0) or 0) for entry in attempts)
        llm_total_tokens = sum(int(entry.get("llm_total_tokens", 0) or 0) for entry in attempts)
        # Useful time = the attempt that actually completed each shard (the
        # highest-numbered primary attempt that exited 0).  Retry time = every
        # other attempt: failed primaries, primaries that were superseded by a
        # later attempt, and every finding-level re-run.  Keeping the two apart
        # is what turns "time excluding retries" into a measured number.
        #
        # A superseded primary can itself have exited 0 -- codex finished, the
        # validator rejected its output -- so an exit-status test alone would
        # count that re-run as useful work and understate the retry tail.
        grouped: dict[str, list[tuple[int, bool, dict[str, Any]]]] = {}
        for entry in attempts:
            base, finding_retry, attempt_no = classify_attempt(entry.get("attempt", ""))
            if base is None:
                continue
            grouped.setdefault(base, []).append((attempt_no, finding_retry, entry))

        useful_by_shard: dict[str, float] = {}
        retry_attempts: list[dict[str, Any]] = []
        for base, entries in grouped.items():
            entries.sort(key=lambda item: item[0])
            winner: dict[str, Any] | None = None
            for _no, finding_retry, entry in entries:
                raw_status = entry.get("exit_status")
                exit_status = int(raw_status) if raw_status is not None else -1
                if not finding_retry and exit_status == 0:
                    winner = entry
            for _no, finding_retry, entry in entries:
                if winner is not None and entry is winner and not finding_retry:
                    useful_by_shard[base] = float(entry.get("wall_seconds", 0) or 0)
                else:
                    retry_attempts.append(entry)
        useful_seconds = sum(useful_by_shard.values())
        retry_seconds = sum(float(entry.get("wall_seconds", 0) or 0) for entry in retry_attempts)
        shard_count = len(useful_by_shard)
        max_useful_shard = max(useful_by_shard.values()) if useful_by_shard else 0.0
        # Lower bound on a retry-free makespan under perfect packing: no
        # schedule can beat either the slowest single shard or the total work
        # divided by the concurrency.
        ideal_makespan = (
            max(useful_seconds / self.concurrency, max_useful_shard)
            if self.concurrency else useful_seconds
        )
        summary = {
            "schema_version": "crbc_phase3_summary.v1",
            "run_id": self.run_id,
            "status": "complete" if final else self.manifest.get("status", "prepared"),
            "generated_at": utc_now(),
            "model": self.model,
            "reasoning_effort": REASONING_EFFORT,
            "module_count": len(self.modules),
            "complete_modules": sum(record["status"] == "complete" for record in module_records.values()),
            "finding_count": sum(len(values) for values in self.findings.values()),
            "completed_findings": sum(len(self.completed_ids(ip)) for ip in self.modules),
            "pending_findings": sum(len(set(self.findings[ip]) - self.completed_ids(ip)) for ip in self.modules),
            "llm_input_tokens": llm_input_tokens,
            "llm_cached_input_tokens": llm_cached_input_tokens,
            "llm_output_tokens": llm_output_tokens,
            "llm_reasoning_output_tokens": llm_reasoning_tokens,
            "llm_total_tokens": llm_total_tokens,
            "active_agents": 0,
            "modules": module_records,
            "shards": shard_records,
            "timing": {
                "average_shard_seconds": round(statistics.mean(durations), 3) if durations else 0.0,
                "median_shard_seconds": round(statistics.median(durations), 3) if durations else 0.0,
                "p95_shard_seconds": round(percentile(durations, 0.95), 3),
                "finding_per_hour": round(sum(len(self.completed_ids(ip)) for ip in self.modules) * 3600 / run_wall, 3),
                "concurrency": self.concurrency,
                "shard_size": self.shard_size,
                "shard_count": shard_count,
                "concurrency_utilization": round(active_seconds / (run_wall * self.concurrency), 4),
                "useful_seconds": round(useful_seconds, 3),
                "useful_parallelism_factor": round(useful_seconds / run_wall, 3),
                "parallel_efficiency": round(
                    useful_seconds / (run_wall * self.concurrency), 4
                ) if self.concurrency else 0.0,
                "ideal_makespan_seconds": round(ideal_makespan, 3),
                "retry_seconds": round(retry_seconds, 3),
                "retry_attempt_count": len(retry_attempts),
                "retry_failure_types": dict(Counter(
                    str(entry.get("retry_reason")) for entry in retry_attempts if entry.get("retry_reason")
                )),
                "worker_wall_seconds_sum": round(active_seconds, 3),
                "script_wall_seconds": round(run_wall, 3),
                "parallelism_factor": round(active_seconds / run_wall, 3),
            },
        }
        atomic_json(self.run_dir / "summary.json", summary)
        atomic_json(self.run_dir / "timing_summary.json", summary["timing"])
        lines = [
            "# Source-Level Review Summary", "",
            f"- Run: `{self.run_id}`",
            f"- Status: `{summary['status']}`",
            f"- Model: `{self.model}` / `{REASONING_EFFORT}`",
            f"- Modules: {summary['complete_modules']}/{summary['module_count']} complete",
            f"- Findings: {summary['completed_findings']}/{summary['finding_count']} complete",
            f"- Pending: {summary['pending_findings']}", "",
            "| Module | Status | Findings | Attempts | Findings/hour |", "|---|---:|---:|---:|---:|",
        ]
        for ip in self.modules:
            record = module_records[ip]
            lines.append(
                f"| {ip} | {record['status']} | {record['completed_findings']}/{record['finding_count']} "
                f"| {record['attempt_count']} | {record['finding_per_hour']:.3f} |"
            )
        (self.run_dir / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.manifest["status"] = "complete" if final else self.manifest.get("status", "prepared")
        self.manifest["updated_at"] = utc_now()
        atomic_json(self.run_dir / "manifest.json", self.manifest)
        self.trace("reports_written", final=final, pending=summary["pending_findings"])


def parser() -> argparse.ArgumentParser:
    package_root = Path(__file__).resolve().parents[2]
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run-id")
    result.add_argument("--repo-root", required=True, help="RTL repository root to review, read-only.")
    result.add_argument("--out-root", required=True, help="Candidate directory containing findings_<module>.json.")
    result.add_argument("--run-root", dest="run_root",
                        default="output/phase3", help="Directory for new Phase 3 run artifacts.")
    result.add_argument("--prompt", default=str(package_root / "config/prompts/phase3/verify_agent.md"))
    result.add_argument("--schema", default=str(package_root / "config/phase3_schema.json"))
    result.add_argument("--fragment-index", help="Optional reference fragment index from extraction.")
    result.add_argument("--selected-file-map", help="Optional selected RTL JSON map; limits frozen input fingerprints.")
    result.add_argument("--modules", help="Comma-separated module subset; otherwise discover findings_<module>.json files.")
    result.add_argument("--codex-bin", default="codex")
    result.add_argument(
        "--model",
        default=os.environ.get("CRBC_PHASE3_MODEL"),
        help=(
            "Codex model to request for source-level review. Defaults to $CRBC_PHASE3_MODEL, "
            "then the provider's <PREFIX>_MODEL. A model must be configured for execution."
        ),
    )
    result.add_argument("--env-file", default=os.environ.get("ENV_FILE", str(package_root / ".env")))
    result.add_argument(
        "--provider-env-prefix", default="CRBC_OPENAI",
        help="Prefix for API_KEY/BASE_URL/MODEL in --env-file or process environment.",
    )
    result.add_argument(
        "--allow-provider-model-mismatch", action="store_true",
        help="Keep the --model request model even if the provider's MODEL metadata differs.",
    )
    result.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    result.add_argument("--shard-size", type=int, default=SHARD_SIZE)
    result.add_argument(
        "--force-finding",
        action="append",
        default=[],
        help="Always include this finding ID in source-level review, even if normal selection filters it out.",
    )
    result.add_argument("--stall-seconds", type=float, default=STALL_SECONDS)
    result.add_argument("--attempt-seconds", type=float, default=ATTEMPT_SECONDS)
    result.add_argument("--interrupt-grace-seconds", type=float, default=INTERRUPT_GRACE_SECONDS)
    result.add_argument("--prepare-only", action="store_true", help="Freeze and validate local inputs without an API key or Codex invocation.")
    result.add_argument("--pilot-only", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        raise SystemExit(f"concurrency must be in [1, {MAX_CONCURRENCY}]")
    if not 1 <= args.shard_size <= SHARD_SIZE:
        raise SystemExit(f"shard size must be in [1, {SHARD_SIZE}]")
    controller = Controller(args)
    try:
        asyncio.run(controller.execute())
    except KeyboardInterrupt:
        controller.reap_active_process_groups()
        controller.trace("controller_interrupted")
        return 130
    except Exception as exc:
        controller.reap_active_process_groups()
        controller.trace("controller_error", error=f"{type(exc).__name__}: {exc}")
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
