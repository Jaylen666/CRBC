"""Bidirectional ref <-> finding matching (forward + reverse, layered merge).

Reference atoms are split by ``ref_kind`` into specific and general, retrieved
in different directions, then merged layer by layer.

Unified scoring (**direction-independent**: forward and reverse share the same
cosine matrix and the same formula):

    score(finding, ref) = W_EMBED * cosine(embed_finding, embed_ref) + W_KW * kw_hit
    kw_hit = sum(len(matched finding keywords)) / sum(len(all finding keywords))

Directions:
- ``general`` ref -> forward: the finding is the query and recalls its top-k
  general refs (general layer, ranked after the specific layer).
- ``specific`` ref -> reverse union forward (specific layer, ranked first):
  - reverse: the ref is the query and recalls its top-n in [1,3] findings
    (catches deletion-type defects, where the finding carries no matching
    signal name).
  - forward (safety net): the finding is the query and recalls its top-k refs
    from the specific pool only, covering anything reverse missed.
  - the two directions are unioned by ``ref_id`` (higher score wins) and
    truncated to ``max_specific``.

Merge (guard rail): a finding's ``ref_clues`` = specific layer (front,
<= max_specific) + general layer (back, <= max_general), each with its own
``min_score`` floor.

This module does **not** rescore findings: it consumes findings + ref atoms
and returns findings carrying ``ref_clues``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import numpy as np

from rtl_bug_agent.phase2.semantic_ag import (
    SemanticAgConfig,
    _encode,
    _l2_normalize,
    _normalize_signal,
)


# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------
@dataclass
class RefMatchConfig:
    # Unified score weights (embedding 0.7 / keyword 0.3)
    w_embed: float = 0.7
    w_kw: float = 0.3

    # Specific layer, reverse direction (guard rail 1: small n + score floor)
    reverse_n: int = 3               # max findings recalled per specific ref (in [1,3])
    reverse_min_score: float = 0.40  # specific-layer floor: skip rather than force a match
    # Specific layer, forward safety net: top-k refs per finding, specific pool only
    specific_forward_k: int = 2

    # General layer, forward direction
    forward_top_k: int = 3           # max general refs recalled per finding
    forward_min_score: float = 0.40  # general-layer floor

    # Merge (guard rail 2): per-finding quota for each layer
    max_specific: int = 4
    max_general: int = 2

    # Minimum keyword substring length (avoids 2-character fragments matching by accident)
    kw_min_substr: int = 3


# ---------------------------------------------------------------------------
# Text / keywords
# ---------------------------------------------------------------------------
def _finding_query_text(f: dict[str, Any]) -> str:
    """Embedding query text for a finding: title + contradiction + signal names."""
    parts = [
        str(f.get("title", "") or ""),
        str(f.get("contradiction", "") or ""),
        " ".join(str(s) for s in (f.get("involved_signals", []) or [])),
    ]
    return "\n".join(p for p in parts if p)


def _norm_kw(k: str) -> str:
    """Normalise a keyword: lowercase + _normalize_signal (strip [..] and port suffixes)."""
    return _normalize_signal(str(k).strip().lower())


def _finding_kw_norms(f: dict[str, Any]) -> list[str]:
    """Normalised finding keywords (= involved_signals), deduplicated, order kept."""
    out: list[str] = []
    seen: set[str] = set()
    for s in f.get("involved_signals", []) or []:
        n = _norm_kw(s)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _ref_kw_norms(a: dict[str, Any]) -> set[str]:
    return {n for n in (_norm_kw(k) for k in (a.get("keywords", []) or [])) if n}


def _kw_hit(finding_kw: list[str], ref_kw: set[str], min_substr: int) -> float:
    """kw_hit = sum(len(matched finding keywords)) / sum(len(all finding keywords)).

    A keyword matches when it equals a ref keyword after normalisation, or when
    the two are substrings of each other with length >= ``min_substr``.  Longer,
    more specific signal names contribute more than short fragments, which
    naturally favours concrete signals.
    """
    total = sum(len(s) for s in finding_kw)
    if total == 0:
        return 0.0
    hit = 0
    for fk in finding_kw:
        matched = fk in ref_kw
        if not matched and len(fk) >= min_substr:
            for rk in ref_kw:
                if len(rk) >= min_substr and (fk in rk or rk in fk):
                    matched = True
                    break
        if matched:
            hit += len(fk)
    return hit / total


# ---------------------------------------------------------------------------
# Loading / splitting refs
# ---------------------------------------------------------------------------
def split_atoms(atoms: list[dict[str, Any]]) -> tuple[list[dict], list[dict]]:
    """Split atoms by ``ref_kind`` into (specific, general).

    Atoms are expected to carry one of those two labels; the extraction
    validator enforces it, so anything else is ignored here.
    """
    specific, general = [], []
    for a in atoms:
        kind = str(a.get("ref_kind", "")).lower()
        if kind == "specific":
            specific.append(a)
        elif kind == "general":
            general.append(a)
    return specific, general


def _clue(a: dict[str, Any], score: float, cos: float, kw: float, layer: str) -> dict[str, Any]:
    clue = {
        "ref_id": a.get("ref_id"),
        "ref_content": a.get("ref_content"),
        "ref_kind": a.get("ref_kind"),
        "keywords": a.get("keywords", []),
        "layer": layer,                    # "specific" | "general"
        "score": round(float(score), 3),
        "cosine": round(float(cos), 3),
        "kw_hit": round(float(kw), 3),
    }
    if isinstance(a.get("source_provenance"), dict):
        clue["source_provenance"] = a["source_provenance"]
    return clue


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def match(
    findings: list[dict[str, Any]],
    atoms: list[dict[str, Any]],
    config: RefMatchConfig | None = None,
    sem_config: SemanticAgConfig | None = None,
    verbose: bool = False,
) -> list[dict[str, Any]]:
    """Attach ``ref_clues`` to each finding (specific layer first, general after).

    Modifies *findings* in place and returns it.
    """
    cfg = config or RefMatchConfig()
    scfg = sem_config or SemanticAgConfig()

    if not findings:
        return findings
    for f in findings:
        f.setdefault("ref_clues", [])

    specific, general = split_atoms(atoms)
    if verbose:
        print(f"  atoms: {len(atoms)}  specific={len(specific)}  general={len(general)}")
    if not specific and not general:
        return findings

    # ── embeddings (encode refs and findings once; after L2 norm the dot product is cosine)
    all_refs = specific + general
    ref_vecs = _l2_normalize(_encode(
        scfg.model_name, [a.get("ref_content", "") for a in all_refs],
        scfg.batch_size, scfg.use_fp16, scfg.hf_home, scfg.offline,
    ))
    q_vecs = _l2_normalize(_encode(
        scfg.model_name, [_finding_query_text(f) for f in findings],
        scfg.batch_size, scfg.use_fp16, scfg.hf_home, scfg.offline,
    ))
    cos = q_vecs @ ref_vecs.T                       # [n_findings, n_refs]

    # ── kw_hit matrix (same shape); score = w_embed*cos + w_kw*kw
    f_kw = [_finding_kw_norms(f) for f in findings]
    r_kw = [_ref_kw_norms(a) for a in all_refs]
    kw = np.zeros_like(cos)
    for i, fk in enumerate(f_kw):
        for j, rk in enumerate(r_kw):
            kw[i, j] = _kw_hit(fk, rk, cfg.kw_min_substr)
    score = cfg.w_embed * cos + cfg.w_kw * kw

    n_spec = len(specific)                          # the first n_spec columns are specific refs

    # ── specific layer: reverse union forward (both confined to the specific pool)
    spec_hits: list[dict[int, tuple]] = [{} for _ in findings]

    def _add_spec(i: int, j: int) -> None:
        s = float(score[i, j])
        if s < cfg.reverse_min_score:                # skip rather than force a match
            return
        prev = spec_hits[i].get(j)
        if prev is None or s > prev[0]:
            spec_hits[i][j] = (s, float(cos[i, j]), float(kw[i, j]))

    # reverse: each specific ref recalls its top-n findings (guard rail 1)
    reverse_n = max(1, min(cfg.reverse_n, 3))       # force n into [1,3]
    for j in range(n_spec):
        for i in np.argsort(-score[:, j])[:reverse_n]:
            _add_spec(int(i), j)

    # forward safety net: each finding recalls its top-k refs from the specific pool
    if n_spec:
        for i in range(len(findings)):
            for j in np.argsort(-score[i, :n_spec])[:cfg.specific_forward_k]:
                _add_spec(i, int(j))

    # ── general layer: forward (each finding recalls its top-k general refs)
    gen_hits: list[list[tuple]] = [[] for _ in findings]
    for i in range(len(findings)):
        cand = []
        for jg in range(len(general)):
            j = n_spec + jg                          # column of this general ref
            s = float(score[i, j])
            if s >= cfg.forward_min_score:
                cand.append((s, float(cos[i, j]), float(kw[i, j]), general[jg]))
        cand.sort(key=lambda x: x[0], reverse=True)
        gen_hits[i] = cand[:cfg.forward_top_k]

    # ── merge: specific layer (front, sorted and truncated) + general layer (back)
    for i, f in enumerate(findings):
        spec_layer = sorted(
            ((s, c, k, specific[j]) for j, (s, c, k) in spec_hits[i].items()),
            key=lambda x: x[0], reverse=True,
        )[:cfg.max_specific]
        gen_layer = gen_hits[i][:cfg.max_general]
        clues = [_clue(a, s, c, k, "specific") for s, c, k, a in spec_layer]
        clues += [_clue(a, s, c, k, "general") for s, c, k, a in gen_layer]
        f["ref_clues"] = clues

    return findings


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------
def load_atoms(path: str) -> list[dict[str, Any]]:
    """Read ref_atoms from <ip>_ref_raw.json or <ip>_ref.json."""
    d = json.load(open(path, encoding="utf-8"))
    return d.get("ref_atoms", []) if isinstance(d, dict) else list(d)


def load_findings(path: str) -> list[dict[str, Any]]:
    """Read findings from findings_*.json (accepts {"findings":[...]} or a bare list)."""
    d = json.load(open(path, encoding="utf-8"))
    if isinstance(d, dict):
        return d.get("findings", []) or []
    return list(d)
