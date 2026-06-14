"""Offline analysis of a committed injection-scan CSV.

Reproducibility, not new data: every headline number in the README must be
re-derivable by anyone from a committed CSV with one command —
`agentprobe analyze <csv>` — rather than taken on trust. This reads the raw
per-attempt rows the harness wrote and recomputes leak rate by defense and by
channel with Wilson 95% CIs, plus a two-proportion test of each channel against
the inbox-email baseline (the basis of the "memory poisoning is worse" finding).

It does NOT call any model: the injection battery is judged by deterministic
detectors, so the numbers are a pure function of the committed CSV.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from agentprobe.metrics import two_proportion_pvalue, wilson_ci

# Display order; any unknown groups are appended alphabetically.
CHANNEL_ORDER = ["email", "document", "webpage", "knowledge_base", "memory"]
DEFENSE_ORDER = ["none", "delimited", "spotlight", "sandwich", "instr_hierarchy", "llm_filter"]
BASELINE_CHANNEL = "email"


@dataclass
class GroupRate:
    name: str
    leaks: int
    n: int

    @property
    def rate(self) -> float:
        return self.leaks / self.n if self.n else 0.0

    @property
    def ci(self) -> tuple[float, float, float]:
        return wilson_ci(self.leaks, self.n)


@dataclass
class AnalysisResult:
    total: GroupRate
    by_defense: list[GroupRate]
    by_channel: list[GroupRate]
    by_probe: list[GroupRate]
    channel_vs_email: dict[str, float]   # channel -> two-proportion p-value vs email


def read_rows(path: str | Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _scored(rows: list[dict]) -> list[dict]:
    """Drop error rows (leaked == "") — they don't count toward any rate."""
    return [r for r in rows if str(r.get("leaked", "")) != ""]


def _counts(rows: list[dict], field: str) -> dict[str, list[int]]:
    c: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        key = str(r.get(field, "?"))
        c[key][0] += int(r["leaked"]) == 1
        c[key][1] += 1
    return c


def _ordered(counts: dict, order: list[str]) -> list[str]:
    known = [k for k in order if k in counts]
    extra = sorted(k for k in counts if k not in order)
    return known + extra


def analyze_injection(path: str | Path) -> AnalysisResult:
    """Recompute the grouped leak rates from a committed injection-scan CSV."""
    raw = read_rows(path)
    if not raw or "leaked" not in raw[0]:
        raise ValueError(
            f"{path} is not an injection-scan CSV (no 'leaked' column). "
            "analyze currently supports injection-scan output."
        )
    rows = _scored(raw)
    total = GroupRate("overall", sum(int(r["leaked"]) == 1 for r in rows), len(rows))

    def grouped(field: str, order: list[str]) -> list[GroupRate]:
        c = _counts(rows, field)
        return [GroupRate(k, c[k][0], c[k][1]) for k in _ordered(c, order)]

    by_defense = grouped("defense", DEFENSE_ORDER)
    by_channel = grouped("channel", CHANNEL_ORDER)
    by_probe = sorted(
        (GroupRate(k, v[0], v[1]) for k, v in _counts(rows, "instruction").items()),
        key=lambda g: -g.rate,
    )

    # Two-proportion test of each channel against the inbox-email baseline.
    cc = _counts(rows, "channel")
    channel_vs_email: dict[str, float] = {}
    base = cc.get(BASELINE_CHANNEL)
    if base:
        for ch, (x, n) in cc.items():
            if ch == BASELINE_CHANNEL:
                continue
            channel_vs_email[ch] = two_proportion_pvalue(x, n, base[0], base[1])
    return AnalysisResult(total, by_defense, by_channel, by_probe, channel_vs_email)
