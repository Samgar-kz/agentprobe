#!/usr/bin/env python3
"""Validate the semantic (LLM-as-judge) oracle against human labels.

Thin wrapper around `agentprobe.oracle_validation` (shared with the
`agentprobe validate-oracle` CLI command, so the two can never diverge). The
headline defense numbers are only trustworthy if the judge that produced them
agrees with a human; this reports agreement, Cohen's kappa, and a confusion
matrix over data/oracle_labeled.jsonl.

Usage:
    export OPENAI_API_KEY=...
    python scripts/validate_oracle.py
    python scripts/validate_oracle.py --dataset data/oracle_labeled.jsonl --min-confidence 0.5
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentprobe.oracle_validation import (  # noqa: E402
    DEFAULT_DATASET,
    format_report,
    validate_oracle,
)


def _parse_args() -> dict:
    cfg = {"dataset": str(DEFAULT_DATASET), "min_confidence": 0.0, "model": None}
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a.startswith("--dataset="):
            cfg["dataset"] = a.split("=", 1)[1]
        elif a == "--dataset" and i + 1 < len(argv):
            cfg["dataset"] = argv[i + 1]
        elif a.startswith("--min-confidence="):
            cfg["min_confidence"] = float(a.split("=", 1)[1])
        elif a.startswith("--model="):
            cfg["model"] = a.split("=", 1)[1]
    return cfg


def main() -> int:
    cfg = _parse_args()
    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY not set. The semantic oracle needs it to run.")
        print("Set it and re-run:  export OPENAI_API_KEY=...  &&  python scripts/validate_oracle.py")
        return 2
    result = validate_oracle(
        dataset=cfg["dataset"], min_confidence=cfg["min_confidence"], model=cfg["model"]
    )
    print(format_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
