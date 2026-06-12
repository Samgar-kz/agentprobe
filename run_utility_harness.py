#!/usr/bin/env python3
"""Utility harness — thin wrapper over the packaged harness.

The implementation now lives in `agentprobe.injection.harness` and is exposed as
`agentprobe utility-scan`. This script is kept for backward compatibility and
delegates to the CLI command.

Run:
    export OPENAI_API_KEY=...
    python run_utility_harness.py --repeats=3 --temp=0.7 --out=utility_results
    python run_utility_harness.py --anthropic --repeats=3

Equivalent:
    agentprobe utility-scan --repeats 3 --temp 0.7 --out utility_results
"""

import sys

from agentprobe.cli import utility_scan


def _parse_and_run() -> None:
    backend = "openai"
    model = None
    repeats = 3
    temp = 0.7
    llm_filter = False
    out = "utility_results"
    for a in sys.argv[1:]:
        if a == "--anthropic":
            backend = "anthropic"
        elif a == "--llm-filter":
            llm_filter = True
        elif a.startswith("--model="):
            model = a.split("=", 1)[1]
        elif a.startswith("--repeats="):
            repeats = int(a.split("=", 1)[1])
        elif a.startswith("--temp="):
            temp = float(a.split("=", 1)[1])
        elif a.startswith("--out="):
            out = a.split("=", 1)[1]
    try:
        utility_scan(
            backend=backend, model=model, repeats=repeats,
            temp=temp, llm_filter=llm_filter, out=out,
        )
    except SystemExit:
        pass


if __name__ == "__main__":
    _parse_and_run()
