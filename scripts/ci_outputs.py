#!/usr/bin/env python3
"""Translate a scan JSON report + exit code into GitHub Action outputs and a
job-summary table. Kept as a standalone script (not inlined in action.yml) so the
composite action stays readable and this logic is unit-testable.

Usage: ci_outputs.py <report.json> <scan_exit_code>

Writes hits/total/success-rate/report-path/outcome to $GITHUB_OUTPUT and a
markdown summary to $GITHUB_STEP_SUMMARY. Falls back to stdout when those env
vars are absent (local runs / tests).
"""

from __future__ import annotations

import json
import os
import sys


def _emit(lines: dict[str, str]) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            for k, v in lines.items():
                f.write(f"{k}={v}\n")
    else:
        for k, v in lines.items():
            print(f"[output] {k}={v}")


def _summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(md + "\n")
    else:
        print(md)


def main() -> int:
    report_path = sys.argv[1] if len(sys.argv) > 1 else "agentprobe-report.json"
    rc = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    total = hits = 0
    rate = 0.0
    target = "?"
    loaded = False
    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)
        stats = data.get("statistics", {})
        total = int(stats.get("total_attacks", 0))
        hits = int(stats.get("hits", 0))
        target = data.get("target", "?")
        rate = (hits / total) if total else 0.0
        loaded = True
    except (OSError, ValueError, KeyError):
        pass  # report missing/unreadable (e.g. scan errored before writing)

    # rc: 0=clean, 2=vulnerabilities over threshold, 1/3=error
    outcome = {0: "pass", 2: "fail"}.get(rc, "error")

    _emit({
        "hits": str(hits),
        "total": str(total),
        "success-rate": f"{rate:.4f}",
        "report-path": report_path,
        "outcome": outcome,
    })

    badge = {"pass": "✅ pass", "fail": "❌ fail", "error": "⚠️ error"}[outcome]
    rows = [
        "### AgentProbe injection scan",
        "",
        f"**Result:** {badge}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Target | `{target}` |",
        f"| Hits / Total | {hits} / {total} |",
        f"| Hit rate | {rate*100:.1f}% |",
        f"| Scan exit code | {rc} |",
    ]
    if not loaded:
        rows.append("| Note | report not found — scan likely errored before writing |")
    _summary("\n".join(rows))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
