"""
LLM view projection — the single allow-list for finding fields sent to an LLM.

Every code path that builds an LLM payload from a finding SHOULD go through
:func:`finding_for_llm`. Direct ``json.dumps(finding)`` or ad-hoc field picking
risks leaking internal fields (trace records, solver workdirs, logs) into
prompts and inflating token cost.

The allow-list is *positive*: a newly added finding field is invisible to the
LLM by default and only becomes visible when explicitly added here.
"""

from __future__ import annotations

from typing import Any

# Finding fields the LLM is allowed to see. ``trace_ref`` and any ``formal``
# internal fields (workdir/log/clock/bind_*) are intentionally absent.
_LLM_VISIBLE_FINDING_FIELDS = (
    "title",
    "severity",
    "verdict",
    "channels",
    "contradiction",
    "involved_signals",
)


def finding_for_llm(finding: dict[str, Any]) -> dict[str, Any]:
    """Project *finding* down to the only fields allowed into an LLM prompt.

    Trace records, trace_ref, and formal internal/debug fields are never
    included. Returns a fresh dict; the input is not mutated.
    """
    return {k: finding.get(k) for k in _LLM_VISIBLE_FINDING_FIELDS}
