#!/usr/bin/env python3
"""Statistical injection harness — thin wrapper over the packaged harness.

The implementation now lives in `agentprobe.injection.harness` and is exposed as
`agentprobe injection-scan`, so the headline results are reproducible from a
plain `pip install agentprobe-injection` (no repo clone, no examples/ on path).
This script is kept for backward compatibility and delegates to the CLI command.

Run:
    export OPENAI_API_KEY=...
    python run_injection_stats.py --repeats=5 --temp=0.7 --out=results
    python run_injection_stats.py --anthropic --model=claude-haiku-4-5 --repeats=5

Equivalent:
    agentprobe injection-scan --repeats 5 --temp 0.7 --out results
"""

import sys

from agentprobe.cli import injection_scan


def _parse_and_run() -> None:
    backend = "openai"
    model = None
    repeats = 5
    temp = 0.7
    llm_filter = False
    out = None
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
        injection_scan(
            backend=backend, model=model, repeats=repeats,
            temp=temp, llm_filter=llm_filter, out=out,
        )
    except SystemExit:
        pass  # the CLI command raises typer.Exit; swallow for script use


if __name__ == "__main__":
    _parse_and_run()
