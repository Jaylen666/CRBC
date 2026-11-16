#!/usr/bin/env python3
"""CLI for reference-atom extraction.

Pass ``--fragment-index`` to extract refs per verified primary source fragment
with source provenance; otherwise extraction walks the module's own
documentation under ``--ip-root``.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rtl_bug_agent.phase2.ref_extract import main


if __name__ == "__main__":
    raise SystemExit(main())
