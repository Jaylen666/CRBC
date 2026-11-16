"""
Trace sidecar — end-to-end traceability for findings.

Design constraints:
- Trace records are written to a JSONL *sidecar* file, keyed by finding id.
- A finding object only ever carries a lightweight ``trace_ref`` pointer, never
  the trace records themselves, so trace volume cannot inflate an LLM payload.
- Trace is produced by deterministic Python only — no LLM call, zero token cost.

The single public entry point is :func:`append_trace`. Every pipeline stage
(chunk / atom / pair / channel_b / phase3) calls it with ``stage`` plus
stage-specific keyword fields, so the schema stays uniform and a finding's
history can be reconstructed from the sidecar.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

# Recognised pipeline stages, in canonical pipeline order. Their order lets a
# report reader see at which stage a finding stopped appearing.
STAGE_ORDER = (
    "chunk",
    "atom",
    "pair",
    "channel_b",
    "phase3",
)

_LOCK = threading.Lock()


class TraceSink:
    """Append-only JSONL sink for trace records.

    Linux guarantees atomic appends below PIPE_BUF (4096 bytes); a process-level
    lock additionally serialises writes so concurrent consistency analyzer workers do not
    interleave partial lines.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False)
        with _LOCK:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def load(self) -> dict[str, list[dict[str, Any]]]:
        """Return ``{finding_id: [records in append order]}``."""
        out: dict[str, list[dict[str, Any]]] = {}
        if not self.path.exists():
            return out
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip a corrupted line rather than abort the report
            fid = str(rec.get("finding_id", ""))
            out.setdefault(fid, []).append(rec)
        return out


def ensure_trace_ref(finding: dict[str, Any], finding_id: str) -> str:
    """Attach a ``trace_ref`` pointer to *finding* and return the id.

    Never attaches trace records to the finding itself. The pointer is
    not on the LLM allow-list (see ``llm_view.py``), so it cannot reach a prompt.
    """
    fid = str(finding_id or finding.get("finding_id") or finding.get("trace_ref") or "")
    if fid:
        finding["trace_ref"] = fid
    return fid


def append_trace(
    finding: dict[str, Any],
    stage: str,
    *,
    sink: TraceSink | None,
    finding_id: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Append one trace record for *finding* at *stage*.

    Parameters
    ----------
    finding:
        The finding dict. Only its ``trace_ref`` pointer is touched; no trace
        record is stored on it.
    stage:
        One of :data:`STAGE_ORDER` (other values are allowed but flagged by the
        report tool as non-canonical).
    sink:
        Destination sidecar. When ``None`` the call is a no-op (legacy mode /
        tracing disabled) so insertion points stay cost-free when unused.
    finding_id:
        Explicit id; defaults to the finding's existing ``finding_id`` /
        ``trace_ref``.
    **fields:
        Stage-specific payload (e.g. ``verdict=...``, ``score=...``).

    Returns the record that was written (or would have been written).
    """
    # Strict no-op when tracing is disabled: do not mutate the finding at all,
    # so legacy output (sink=None) is byte-for-byte unchanged.
    fid = str(
        finding_id
        or finding.get("finding_id")
        or finding.get("trace_ref")
        or ""
    )
    record = {"finding_id": fid, "stage": str(stage), **fields}
    if sink is None:
        return record
    ensure_trace_ref(finding, fid)
    sink.append(record)
    return record
