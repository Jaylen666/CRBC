#!/usr/bin/env python3
"""Materialize verified Markdown fragments into per-module reference documents."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HEADING_RE = re.compile(br"^(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*(?:\r?\n|$)")
FENCE_RE = re.compile(br"^[ \t]*(`{3,}|~{3,})")


class ValidationError(Exception):
    """Raised when a materialization invariant is violated."""


@dataclass(frozen=True)
class Heading:
    path: tuple[str, ...]
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    content: bytes


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_headings(data: bytes) -> list[Heading]:
    """Parse ATX heading subtrees without treating fenced code as Markdown."""
    raw: list[tuple[int, int, int, str]] = []
    offset = 0
    in_fence: bytes | None = None
    for line_no, line in enumerate(data.splitlines(keepends=True), start=1):
        fence = FENCE_RE.match(line)
        if fence:
            marker = fence.group(1)
            if in_fence is None:
                in_fence = marker[:1]
            elif marker.startswith(in_fence):
                in_fence = None
        if in_fence is None:
            match = HEADING_RE.match(line)
            if match:
                raw.append((len(match.group(1)), line_no, offset, match.group(2).decode("utf-8").strip()))
        offset += len(line)

    headings: list[Heading] = []
    stack: list[str] = []
    total_lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    for index, (level, line_start, byte_start, title) in enumerate(raw):
        stack = stack[: level - 1]
        stack.append(title)
        byte_end = len(data)
        line_end = total_lines
        for later_level, later_line, later_start, _ in raw[index + 1 :]:
            if later_level <= level:
                byte_end = later_start
                line_end = later_line - 1
                break
        headings.append(Heading(tuple(stack), line_start, line_end, byte_start, byte_end, data[byte_start:byte_end]))
    return headings


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("schema_version") != 2:
        raise ValidationError("expected manifest schema_version 2")
    return manifest


def checked_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise ValidationError(f"path escapes Caliptra root: {relative}")
    return path


def checked_index_path(manifest_path: Path, relative: str) -> Path:
    path = (manifest_path.parent / relative).resolve()
    if path != manifest_path.parent and manifest_path.parent not in path.parents:
        raise ValidationError(f"index path escapes manifest directory: {relative}")
    return path


def resolve(manifest: dict[str, Any], manifest_path: Path) -> tuple[Path, dict[str, dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], Path]:
    root = Path(manifest["caliptra_root"]).resolve()
    if not root.is_dir():
        raise ValidationError(f"missing Caliptra root: {root}")
    source_order = manifest["source_order"]
    if len(source_order) != len(set(source_order)):
        raise ValidationError("duplicate source IDs in source_order")

    sources: dict[str, dict[str, Any]] = {}
    for source_id, source in manifest["sources"].items():
        if source_id not in source_order:
            raise ValidationError(f"source omitted from source_order: {source_id}")
        path = checked_path(root, source["path"])
        if not path.is_file():
            raise ValidationError(f"missing source {source_id}: {path}")
        data = path.read_bytes()
        if digest(data) != source["sha256"]:
            raise ValidationError(f"source hash drift: {source_id}")
        sources[source_id] = {"path": path, "relative_path": source["path"], "sha256": source["sha256"], "headings": parse_headings(data)}

    targets: list[dict[str, Any]] = []
    destinations: set[Path] = set()
    assigned: set[str] = set()
    for target in manifest["targets"]:
        ip = target["ip"]
        classification = target["classification"]
        extractable = target["extractable"]
        if classification not in {"primary", "architecture_context"}:
            raise ValidationError(f"invalid classification for {ip}: {classification}")
        if not isinstance(extractable, bool) or extractable != (classification == "primary"):
            raise ValidationError(f"invalid extractable value for {ip}")
        if ip in assigned:
            raise ValidationError(f"duplicate target IP: {ip}")
        assigned.add(ip)
        destination = checked_path(root, target["output"])
        if destination.name != f"{ip}.md":
            raise ValidationError(f"invalid output basename for {ip}: {destination.name}")
        if not destination.parent.is_dir():
            raise ValidationError(f"missing config directory for {ip}: {destination.parent}")
        if destination in destinations:
            raise ValidationError(f"duplicate output destination: {destination}")
        destinations.add(destination)

        fragments: list[dict[str, Any]] = []
        seen_ranges: set[tuple[str, int, int]] = set()
        prior_order = (-1, -1)
        for selector in target["fragments"]:
            source_id = selector["source"]
            source = sources.get(source_id)
            if source is None:
                raise ValidationError(f"unknown source {source_id} for {ip}")
            heading_path = tuple(selector["heading_path"])
            matches = [heading for heading in source["headings"] if heading.path == heading_path]
            if len(matches) != 1:
                raise ValidationError(f"selector for {ip} resolves to {len(matches)} headings: {source_id}:{' / '.join(heading_path)}")
            heading = matches[0]
            content_sha256 = digest(heading.content)
            if content_sha256 != selector["sha256"]:
                raise ValidationError(f"fragment hash drift: {ip}:{' / '.join(heading_path)}")
            ordering = (source_order.index(source_id), heading.byte_start)
            if ordering < prior_order:
                raise ValidationError(f"out-of-order fragments for {ip}")
            prior_order = ordering
            key = (source_id, heading.byte_start, heading.byte_end)
            if key in seen_ranges:
                raise ValidationError(f"duplicate fragment for {ip}: {' / '.join(heading_path)}")
            seen_ranges.add(key)
            fragments.append({"source_id": source_id, "source_path": source["relative_path"], "source_sha256": source["sha256"], "heading": heading, "content_sha256": content_sha256})
        if not fragments:
            raise ValidationError(f"target {ip} has no fragments")
        targets.append({"ip": ip, "output": target["output"], "destination": destination, "classification": classification, "extractable": extractable, "fragments": fragments, "legacy_sha256": target.get("legacy_sha256")})

    skipped = set(manifest.get("skipped", {}))
    if assigned.intersection(skipped):
        raise ValidationError(f"assigned and skipped IPs overlap: {sorted(assigned.intersection(skipped))}")

    retirements: list[dict[str, Any]] = []
    retirement_paths: set[Path] = set()
    for retirement in manifest.get("retirements", []):
        path = checked_path(root, retirement["output"])
        if path in destinations or path in retirement_paths:
            raise ValidationError(f"duplicate managed or retirement path: {path}")
        retirement_paths.add(path)
        retirements.append({"path": path, "output": retirement["output"], "legacy_sha256": retirement["legacy_sha256"]})

    index_path = checked_index_path(manifest_path, manifest["fragment_index"])
    return root, sources, targets, retirements, index_path


def payload(target: dict[str, Any]) -> bytes:
    return b"".join(fragment["heading"].content for fragment in target["fragments"])


def manifest_hash(manifest_path: Path) -> str:
    return digest(manifest_path.read_bytes())


def build_index(manifest_path: Path, root: Path, targets: list[dict[str, Any]]) -> bytes:
    records: list[dict[str, Any]] = []
    for target in targets:
        offset = 0
        output = payload(target)
        for fragment in target["fragments"]:
            content = fragment["heading"].content
            heading = fragment["heading"]
            unit_id = f"{fragment['source_path']}:{heading.line_start}-{heading.line_end}:{fragment['content_sha256']}"
            records.append({
                "unit_id": unit_id,
                "ip": target["ip"],
                "classification": target["classification"],
                "extractable": target["extractable"],
                "generated_output": target["output"],
                "output_byte_start": offset,
                "output_byte_end": offset + len(content),
                "output_sha256": digest(output),
                "source_id": fragment["source_id"],
                "source_path": fragment["source_path"],
                "source_sha256": fragment["source_sha256"],
                "heading_path": list(heading.path),
                "line_start": heading.line_start,
                "line_end": heading.line_end,
                "byte_start": heading.byte_start,
                "byte_end": heading.byte_end,
                "content_sha256": fragment["content_sha256"],
                "authority": "normative" if target["classification"] == "primary" else "architecture_context",
                "scope_ips": [target["ip"]],
            })
            offset += len(content)
    index = {
        "schema_version": 1,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_hash(manifest_path),
        "caliptra_root": str(root),
        "fragments": records,
    }
    return (json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def print_plan(targets: list[dict[str, Any]], retirements: list[dict[str, Any]], index_path: Path) -> None:
    for target in targets:
        print(f"{target['classification']} extractable={target['extractable']} {target['ip']}: {target['destination']}")
        for fragment in target["fragments"]:
            heading = fragment["heading"]
            print(f"  {fragment['source_id']}:{heading.line_start}-{heading.line_end} {' / '.join(heading.path)} [{fragment['content_sha256']}]")
    for retirement in retirements:
        print(f"retire: {retirement['path']}")
    print(f"fragment index: {index_path}")


def ensure_absent(targets: list[dict[str, Any]], index_path: Path) -> None:
    collisions = [str(target["destination"]) for target in targets if target["destination"].exists()]
    if index_path.exists():
        collisions.append(str(index_path))
    if collisions:
        raise ValidationError("output collision(s); no files were written:\n" + "\n".join(collisions))


def write_temp(destination: Path, content: bytes) -> Path:
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temp = Path(temp_name)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return temp


def apply(targets: list[dict[str, Any]], index_path: Path, index_bytes: bytes) -> None:
    ensure_absent(targets, index_path)
    staged: list[tuple[Path, Path]] = []
    created: list[tuple[Path, bytes]] = []
    try:
        for target in targets:
            staged.append((write_temp(target["destination"], payload(target)), target["destination"]))
        staged.append((write_temp(index_path, index_bytes), index_path))
        ensure_absent(targets, index_path)
        for temp, destination in staged:
            content = temp.read_bytes()
            os.replace(temp, destination)
            created.append((destination, content))
    except Exception:
        for temp, _ in staged:
            temp.unlink(missing_ok=True)
        for destination, content in created:
            if destination.is_file() and destination.read_bytes() == content:
                destination.unlink()
        raise


def backup_existing(paths: list[Path]) -> dict[Path, Path]:
    backups: dict[Path, Path] = {}
    for path in paths:
        if path.is_file():
            backups[path] = write_temp(path, path.read_bytes())
    return backups


def restore(backups: dict[Path, Path], created: set[Path]) -> None:
    for path in created:
        if path not in backups:
            path.unlink(missing_ok=True)
    for path, backup in backups.items():
        if backup.exists():
            os.replace(backup, path)


def indexed_output_hashes(index_path: Path, root: Path) -> dict[Path, set[str]]:
    if not index_path.is_file():
        return {}
    try:
        with index_path.open("r", encoding="utf-8") as handle:
            index = json.load(handle)
    except (OSError, ValueError) as error:
        raise ValidationError(f"invalid existing fragment index: {index_path}") from error
    if index.get("schema_version") != 1 or not isinstance(index.get("fragments"), list):
        raise ValidationError(f"invalid existing fragment index schema: {index_path}")

    hashes: dict[Path, set[str]] = {}
    for record in index["fragments"]:
        if not isinstance(record, dict):
            raise ValidationError(f"invalid existing fragment index record: {index_path}")
        output = record.get("generated_output")
        output_hash = record.get("output_sha256")
        if not isinstance(output, str) or not isinstance(output_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", output_hash):
            raise ValidationError(f"invalid existing fragment index output hash: {index_path}")
        destination = checked_path(root, output)
        hashes.setdefault(destination, set()).add(output_hash)
    if any(len(output_hashes) != 1 for output_hashes in hashes.values()):
        raise ValidationError(f"inconsistent output hashes in existing fragment index: {index_path}")
    return hashes


def regenerate(root: Path, targets: list[dict[str, Any]], retirements: list[dict[str, Any]], index_path: Path, index_bytes: bytes) -> None:
    destinations = [target["destination"] for target in targets]
    prior_hashes = indexed_output_hashes(index_path, root)
    for target in targets:
        destination = target["destination"]
        if destination.exists():
            allowed_hashes = set(prior_hashes.get(destination, set()))
            if target["legacy_sha256"]:
                allowed_hashes.add(target["legacy_sha256"])
            if not allowed_hashes or digest(destination.read_bytes()) not in allowed_hashes:
                raise ValidationError(f"managed output has unexpected checkpoint content: {destination}")
    for retirement in retirements:
        if retirement["path"].is_file() and digest(retirement["path"].read_bytes()) != retirement["legacy_sha256"]:
            raise ValidationError(f"retirement target has unexpected content: {retirement['path']}")

    managed_paths = destinations + [retirement["path"] for retirement in retirements] + [index_path]
    backups = backup_existing(managed_paths)
    staged: list[tuple[Path, Path]] = []
    created: set[Path] = set()
    try:
        for target in targets:
            staged.append((write_temp(target["destination"], payload(target)), target["destination"]))
        staged.append((write_temp(index_path, index_bytes), index_path))
        for temp, destination in staged:
            os.replace(temp, destination)
            created.add(destination)
        for retirement in retirements:
            retirement["path"].unlink(missing_ok=True)
            created.add(retirement["path"])
    except Exception:
        for temp, _ in staged:
            temp.unlink(missing_ok=True)
        restore(backups, created)
        raise
    finally:
        for backup in backups.values():
            backup.unlink(missing_ok=True)


def verify(targets: list[dict[str, Any]], retirements: list[dict[str, Any]], index_path: Path, index_bytes: bytes) -> None:
    failures: list[str] = []
    for target in targets:
        expected = payload(target)
        destination = target["destination"]
        if not destination.is_file():
            failures.append(f"missing: {destination}")
        elif destination.read_bytes() != expected:
            failures.append(f"content mismatch: {destination}")
    for retirement in retirements:
        if retirement["path"].exists():
            failures.append(f"retired output still exists: {retirement['path']}")
    if not index_path.is_file():
        failures.append(f"missing fragment index: {index_path}")
    elif index_path.read_bytes() != index_bytes:
        failures.append(f"fragment index mismatch: {index_path}")
    if failures:
        raise ValidationError("verification failed:\n" + "\n".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True, help="Explicit schema-v2 document-fragment manifest")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--apply", action="store_true")
    modes.add_argument("--regenerate", action="store_true")
    modes.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    args.manifest = args.manifest.expanduser().resolve()
    try:
        manifest = load_manifest(args.manifest)
        root, _, targets, retirements, index_path = resolve(manifest, args.manifest)
        index_bytes = build_index(args.manifest, root, targets)
        if args.plan:
            print_plan(targets, retirements, index_path)
        elif args.check:
            ensure_absent(targets, index_path)
            print(f"preflight passed: {len(targets)} outputs are absent")
        elif args.apply:
            apply(targets, index_path, index_bytes)
            print(f"materialized {len(targets)} documents")
        elif args.regenerate:
            regenerate(root, targets, retirements, index_path, index_bytes)
            verify(targets, retirements, index_path, index_bytes)
            print(f"regenerated {len(targets)} documents and retired {len(retirements)} outputs")
        else:
            verify(targets, retirements, index_path, index_bytes)
            print(f"verified {len(targets)} documents and fragment index")
    except (OSError, ValueError, ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
