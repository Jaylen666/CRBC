from __future__ import annotations

import re
from collections import Counter
from typing import Iterable
from pathlib import Path

from rtl_bug_agent.schema import RtlChunk


SV_KEYWORDS = {
    "always", "always_comb", "always_ff", "always_latch", "and", "assign", "automatic",
    "begin", "bit", "case", "casex", "casez", "default", "else", "end", "endcase",
    "endfunction", "endmodule", "endpackage", "endtask", "enum", "for", "function",
    "generate", "genvar", "if", "import", "inout", "input", "int", "integer", "localparam",
    "logic", "module", "negedge", "or", "output", "package", "parameter", "posedge",
    "return", "signed", "struct", "task", "typedef", "unique", "unsigned", "wire",
}


def chunk_sv_files(
    rtl_dir: str | Path,
    client: "OpenAICompatibleClient | None" = None,
    prefilter_max_tokens: int = 4000,
    rtl_files: Iterable[str | Path] | None = None,
) -> list[RtlChunk]:
    """Chunk all .sv files in *rtl_dir*.

    If *client* is given, each file is pre-screened by an LLM that
    classifies sections as BEHAVIORAL / STRUCTURAL.  Purely repetitive
    structural sections (register instances, generated wire lists) are
    skipped during chunking.
    """
    from rtl_bug_agent.rtl.prefilter import classify_sections

    if rtl_files is None:
        paths = sorted(
            list(Path(rtl_dir).glob("*.sv")) + list(Path(rtl_dir).glob("*.v"))
        )
    else:
        paths = sorted({Path(path) for path in rtl_files if Path(path).suffix.lower() in {".sv", ".v"}})
    chunks: list[RtlChunk] = []
    total = len(paths)

    for idx, path in enumerate(paths):
        # LLM pre-filter for structural sections
        skip_ranges: list[tuple[int, int]] = []
        if client:
            try:
                skip_ranges = classify_sections(
                    path, client, max_tokens=prefilter_max_tokens
                )
            except Exception:
                pass  # fall back to full chunking

        chunks.extend(chunk_sv_file(path, skip_ranges=skip_ranges))

        if skip_ranges:
            total_lines = sum(e - s + 1 for s, e in skip_ranges)
            print(
                f"  [{idx + 1}/{total}] {path.name}: "
                f"skipped {len(skip_ranges)} structural section(s) "
                f"({total_lines} lines)"
            )

    return chunks


def chunk_sv_file(
    path: str | Path,
    skip_ranges: list[tuple[int, int]] | None = None,
) -> list[RtlChunk]:
    src_path = Path(path)
    lines = src_path.read_text(encoding="utf-8").splitlines()
    scopes = _scope_by_line(lines)

    # Add pre-filter structural skip ranges as "structural_skip" spans
    protected: list[tuple[int, int, str, str]] = []
    for start, end in (skip_ranges or []):
        protected.append((start, end, "structural_skip", f"struct_{start}_{end}"))

    i = 1
    while i <= len(lines):
        clean = _strip_line_comment(lines[i - 1])
        if _starts_function_or_task(clean):
            end = _find_until(lines, i, (r"^\s*endfunction\b", r"^\s*endtask\b"))
            protected.append((i, end, "function_task", _block_label(clean, i)))
            i = end + 1
            continue
        if _starts_always(clean):
            end = _find_begin_end_block(lines, i)
            kind = _always_kind(clean)
            protected.append((i, end, kind, _block_label(clean, i)))
            i = end + 1
            continue
        if _starts_generate_for(clean):
            end = _find_begin_end_block(lines, i)
            protected.append((i, end, "generate_for", _block_label(clean, i)))
            i = end + 1
            continue
        i += 1

    all_spans: list[tuple[int, int, str, str]] = protected[:]
    all_spans.sort(key=lambda item: item[0])

    other_spans = _find_uncovered_spans(lines, all_spans, max_lines=140)
    all_spans.extend(other_spans)
    all_spans.sort(key=lambda item: item[0])

    counters: Counter[str] = Counter()
    chunks: list[RtlChunk] = []
    for start, end, kind, label in all_spans:
        if not _has_meaningful_code(lines[start - 1:end]):
            continue
        module = _dominant_scope(scopes, start, end)
        safe_scope = _safe_id(module or src_path.stem)
        safe_kind = _safe_id(kind)
        safe_label = _safe_id(label)[:56] or f"line_{start}"
        base = f"{safe_scope}__{safe_kind}__{safe_label}"
        counters[base] += 1
        chunk_id = f"{base}__{counters[base]:03d}"
        code = "\n".join(lines[start - 1:end])
        chunks.append(
            RtlChunk(
                chunk_id=chunk_id,
                kind=kind,
                source_file=str(src_path),
                module=module,
                line_start=start,
                line_end=end,
                title=_title(kind, label, module, start, end),
                context_summary=_context_summary(kind, module, start, end),
                code=code,
                dependencies=_extract_identifiers(code),
            )
        )

    # Post-processing: merge adjacent continuous_region chunks that were
    # artificially split (e.g. by the max_lines cap) but belong to the same
    # semantic region.  Only merges chunks of the same kind with no semantic
    # boundary (always / function / generate) between them.
    chunks = _merge_adjacent_same_kind_chunks(chunks, gap_threshold=2)
    return chunks


def _scope_by_line(lines: list[str]) -> dict[int, str | None]:
    scope: str | None = None
    result: dict[int, str | None] = {}
    for idx, raw in enumerate(lines, start=1):
        clean = _strip_line_comment(raw)
        module_match = re.match(r"^\s*module\s+([A-Za-z_][A-Za-z0-9_$]*)\b", clean)
        package_match = re.match(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_$]*)\b", clean)
        if module_match:
            scope = module_match.group(1)
        elif package_match:
            scope = package_match.group(1)
        result[idx] = scope
        if re.match(r"^\s*endmodule\b", clean) or re.match(r"^\s*endpackage\b", clean):
            scope = None
    return result


def _strip_line_comment(line: str) -> str:
    return re.sub(r"//.*$", "", line)


def _starts_always(line: str) -> bool:
    return bool(re.match(r"^\s*always(?:_(?:comb|ff|latch))?\b", line))


def _starts_function_or_task(line: str) -> bool:
    return bool(re.match(r"^\s*(?:function|task)\b", line))


def _starts_generate_for(line: str) -> bool:
    return bool(re.match(r"^\s*for\s*\(\s*genvar\b", line))


def _always_kind(line: str) -> str:
    match = re.match(r"^\s*(always(?:_(?:comb|ff|latch))?)\b", line)
    return match.group(1) if match else "always"


def _block_label(line: str, start: int) -> str:
    named = re.search(r"\bbegin\s*:\s*([A-Za-z_][A-Za-z0-9_$]*)", line)
    if named:
        return named.group(1)
    func = re.search(r"\b(?:function|task)\b.*?\b([A-Za-z_][A-Za-z0-9_$]*)\s*(?:\(|;)", line)
    if func:
        return func.group(1)
    return f"line_{start}"


def _find_until(lines: list[str], start: int, end_patterns: tuple[str, ...]) -> int:
    for idx in range(start, len(lines) + 1):
        clean = _strip_line_comment(lines[idx - 1])
        if any(re.match(pattern, clean) for pattern in end_patterns):
            return idx
    return len(lines)


def _find_begin_end_block(lines: list[str], start: int) -> int:
    depth = 0
    seen_begin = False
    for idx in range(start, len(lines) + 1):
        clean = _strip_line_comment(lines[idx - 1])
        begins = len(re.findall(r"\bbegin\b", clean))
        ends = len(re.findall(r"\bend\b", clean))
        depth += begins
        if begins:
            seen_begin = True
        depth -= ends
        if seen_begin and depth <= 0:
            return idx
        # Verilog "always" blocks without begin/end: extend until
        # we hit a bare keyword at the start of a line (new block,
        # assign, instance, etc.)
        if not seen_begin:
            if _is_continuation(clean):
                continue
            # Don't end on the first line's semicolon — Verilog always
            # blocks without begin/end may span multiple lines
            if idx > start and ";" in clean:
                return idx
    return len(lines)


def _is_continuation(line: str) -> bool:
    """Return True if *line* looks like it continues the current block."""
    stripped = line.strip()
    if not stripped:
        return True  # blank lines continue
    if stripped.startswith(("//", "`")):
        return True
    # Continuation keywords
    if re.match(r"^(if|else|else\s+if|case|for|while|endcase|end\b)",
                stripped):
        return True
    # Line starts with a signal name or register assignment (indented)
    if re.match(r"^[a-zA-Z_]", stripped) and not re.match(
        r"^(module|endmodule|always|assign|wire|reg|input|output|inout|"
        r"parameter|localparam|function|task|generate|endgenerate)",
        stripped,
    ):
        return True
    return False


def _find_uncovered_spans(
    lines: list[str], covered_spans: list[tuple[int, int, str, str]], max_lines: int
) -> list[tuple[int, int, str, str]]:
    spans: list[tuple[int, int, str, str]] = []
    start: int | None = None
    last_meaningful: int | None = None

    def flush(end: int) -> None:
        nonlocal start, last_meaningful
        if start is not None and last_meaningful is not None:
            label = _other_label(lines[start - 1:last_meaningful])
            spans.append((start, last_meaningful, "continuous_region", label))
        start = None
        last_meaningful = None

    for idx in range(1, len(lines) + 1):
        if _covered(idx, covered_spans):
            flush(idx - 1)
            continue
        raw = lines[idx - 1]
        meaningful = bool(_strip_line_comment(raw).strip()) and not _strip_line_comment(raw).strip().startswith("`ASSERT")
        if not meaningful:
            if start is not None and last_meaningful is not None and idx - last_meaningful > 14:
                flush(idx - 1)
            continue
        if start is None:
            start = idx
        last_meaningful = idx
        if idx - start + 1 >= max_lines:
            flush(idx)
    flush(len(lines))
    return spans


def _other_label(lines: list[str]) -> str:
    joined = "\n".join(lines[:20])
    for pattern in (
        r"^\s*module\s+([A-Za-z_][A-Za-z0-9_$]*)",
        r"^\s*package\s+([A-Za-z_][A-Za-z0-9_$]*)",
        r"^\s*typedef\s+.*?\b([A-Za-z_][A-Za-z0-9_$]*)\s*;",
        r"^\s*localparam\s+.*?\b([A-Za-z_][A-Za-z0-9_$]*)\b",
        r"^\s*([A-Za-z_][A-Za-z0-9_$]*)\s+u_([A-Za-z_][A-Za-z0-9_$]*)\b",
    ):
        match = re.search(pattern, joined, flags=re.MULTILINE)
        if match:
            return "_".join(part for part in match.groups() if part)
    return "declarations_or_instances"


def _covered(line_no: int, spans: list[tuple[int, int, str, str]]) -> bool:
    return any(start <= line_no <= end for start, end, _, _ in spans)


def _dominant_scope(scopes: dict[int, str | None], start: int, end: int) -> str | None:
    names = [scopes.get(line_no) for line_no in range(start, end + 1) if scopes.get(line_no)]
    if not names:
        return None
    return Counter(names).most_common(1)[0][0]


def _has_meaningful_code(lines: list[str]) -> bool:
    for raw in lines:
        clean = _strip_line_comment(raw).strip()
        if clean and not clean.startswith("`ASSERT"):
            return True
    return False


def _extract_identifiers(code: str, limit: int = 40) -> list[str]:
    code_without_comments = "\n".join(_strip_line_comment(line) for line in code.splitlines())
    identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_$]*\b", code_without_comments)
    counts: Counter[str] = Counter(
        ident for ident in identifiers if ident not in SV_KEYWORDS and not ident.startswith("ASSERT")
    )
    return [ident for ident, _ in counts.most_common(limit)]


def _safe_id(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "chunk"


def _title(kind: str, label: str, module: str | None, start: int, end: int) -> str:
    scope = module or "file"
    return f"{scope}: {kind} {label} ({start}-{end})"


def _context_summary(kind: str, module: str | None, start: int, end: int) -> str:
    scope = module or "file scope"
    if kind.startswith("always"):
        return f"{kind} procedural block in {scope}, lines {start}-{end}."
    if kind == "continuous_region":
        return (f"continuous non-procedural logic in {scope}, covering declarations, "
                f"instantiations, or direct combinational assignments, lines {start}-{end}.")
    if kind == "function_task":
        return f"function or task definition in {scope}, lines {start}-{end}."
    return (f"declaration, instantiation, or register context in {scope}, "
            f"lines {start}-{end}.")


def _merge_adjacent_same_kind_chunks(
    chunks: list[RtlChunk], gap_threshold: int = 2
) -> list[RtlChunk]:
    """Merge adjacent same-kind chunks that were artificially split (e.g. by
    the max_lines cap in _find_uncovered_spans), but that belong to a single
    semantic region with no always/function/generate boundary between them.

    Only ``continuous_region`` chunks are candidates for merging, because they
    represent the "everything else" that the chunker didn't classify as a
    named procedural block.  A gap of up to *gap_threshold* lines (inclusive)
    is tolerated — this handles trivial whitespace or single-line separators
    that don't constitute a real semantic boundary.
    """
    if len(chunks) <= 1:
        return chunks

    # Sort by source_file, then line_start
    sorted_chunks = sorted(chunks, key=lambda c: (c.source_file, c.line_start))

    merged: list[RtlChunk] = []
    run: list[RtlChunk] = []

    for chunk in sorted_chunks:
        if not run:
            run.append(chunk)
            continue

        last = run[-1]
        same_file = chunk.source_file == last.source_file
        same_kind = chunk.kind == last.kind
        mergeable_kind = chunk.kind == "continuous_region"
        adjacent = (chunk.line_start - last.line_end) <= gap_threshold

        if same_file and same_kind and mergeable_kind and adjacent:
            run.append(chunk)
        else:
            merged.append(_collapse_run(run))
            run = [chunk]

    if run:
        merged.append(_collapse_run(run))

    # Restore original file ordering (first appearance)
    file_order: dict[str, int] = {}
    for idx, c in enumerate(chunks):
        file_order.setdefault(c.source_file, idx)
    merged.sort(key=lambda c: (file_order.get(c.source_file, 0), c.line_start))
    return merged



def _collapse_run(run: list[RtlChunk]) -> RtlChunk:
    """Collapse a run of same-kind chunks into a single RtlChunk."""
    if len(run) == 1:
        return run[0]

    first, last = run[0], run[-1]
    combined_code = "\n".join(c.code for c in run)
    combined_deps = list(dict.fromkeys(
        dep for c in run for dep in (c.dependencies or [])
    ))[:40]

    merged = RtlChunk(
        chunk_id=first.chunk_id,  # keep the first chunk's id
        kind=first.kind,
        source_file=first.source_file,
        module=first.module,
        line_start=first.line_start,
        line_end=last.line_end,
        title=_title(
            first.kind,
            f"merged_{len(run)}_regions",
            first.module,
            first.line_start,
            last.line_end,
        ),
        context_summary=(
            f"merged {len(run)} adjacent continuous regions, "
            f"lines {first.line_start}-{last.line_end}."
        ),
        code=combined_code,
        dependencies=combined_deps,
    )
    return merged
