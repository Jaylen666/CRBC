#!/usr/bin/env python3
"""Run the CRBC source-level arbiter (controller)."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rtl_bug_agent.phase3.controller import main

if __name__ == "__main__":
    raise SystemExit(main())
