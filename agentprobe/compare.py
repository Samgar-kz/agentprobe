"""Regression comparison between two AgentProbe scan reports.

This turns the harness from a one-shot measurement into an engineering workflow:
run a scan, commit the JSON, run it again later, and `compare` the two to see
whether your agent's leak rate moved — and crucially whether the move is
statistically *real* or just noise. A naive diff (7.2% -> 2.8%) on a small N is
meaningless; here a per-group change is only flagged `improved`/`regressed` when a
two-proportion test clears alpha. Everything else is "within noise".

Designed to gate CI: `agentprobe compare a.json b.json` exits 2 on a significant
regression, mirroring the GitHub Action's exit-code contract (0 clean, 2 finding,
1 error).

Supported report formats (auto-detected):
  * `scan`       — engine report (statistics + by_category + results)
  * `injection`  — injection-scan bundle ({meta, rows} with a `leaked` column)
  * `utility`    — utility-scan bundle ({meta, rows} with an `outcome` column)

Two reports can only be compared if they are the same kind.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agentprobe.metrics import two_proportion_pvalue

# Significance threshold for calling a change real rather than noise.
SIG_ALPHA = 0.05

# Maps the user-facing `--by` dimension to the row field for harness reports.
_INJECTION_GROUP_FIELD = {
    "probe": "instruction",
    "defense": "defense",
    "carrier": "carrier",
    "category": "category",
}


@dataclass
class NormalizedReport:
    """A report reduced to (positives, n) counts overall and per group."""

    kind: str                              # "scan" | "injection" | "utility"
    label: str                             # header label (target or backend/model)
    metric_name: str                       # "Hit rate" | "Leak rate" | "Success rate"
    lower_is_better: bool
    group_dim: str                         # "category" | "probe" | "defense" | ...
    overall: tuple[int, int]               # (positives, n)
    groups: dict[str, tuple[int, int]]     # name -> (positives, n)


@dataclass
class GroupDelta:
    """The change for one group (or the overall total) between two reports."""

    name: str
    old: tuple[int, int] | None            # (pos, n); None if absent in old
    new: tuple[int, int] | None            # (pos, n); None if absent in new
    p_value: float
    status: str                            # improved | regressed | flat | added | removed

    @staticmethod
    def _rate(t: tuple[int, int] | None) -> float | None:
        if t is None or t[1] == 0:
            return None if t is None else 0.0
        return t[0] / t[1]

    @property
    def old_rate(self) -> float | None:
        return self._rate(self.old)

    @property
    def new_rate(self) -> float | None:
        return self._rate(self.new)

    @property
    def delta_pp(self) -> float | None:
        o, n = self.old_rate, self.new_rate
        if o is None or n is None:
            return None
        return (n - o) * 100.0


@dataclass
class ComparisonResult:
    kind: str
    metric_name: str
    lower_is_better: bool
    group_dim: str
    old_label: str
    new_label: str
    overall: GroupDelta
    groups: list[GroupDelta]

    @property
    def regressed(self) -> list[GroupDelta]:
        return [g for g in self.groups if g.status == "regressed"]

    @property
    def improved(self) -> list[GroupDelta]:
        return [g for g in self.groups if g.status == "improved"]

    @property
    def flat(self) -> list[GroupDelta]:
        return [g for g in self.groups if g.status == "flat"]

    @property
    def added(self) -> list[GroupDelta]:
        return [g for g in self.groups if g.status == "added"]

    @property
    def removed(self) -> list[GroupDelta]:
        return [g for g in self.groups if g.status == "removed"]

    @property
    def has_regression(self) -> bool:
        """True if the overall rate or any group regressed significantly.

        This is the CI gate: a significant worsening fails the build. Added/removed
        groups don't count — they're coverage changes, not regressions of existing
        coverage.
        """
        return self.overall.status == "regressed" or bool(self.regressed)


# --------------------------------------------------------------------------- #
# Loading & normalization
# --------------------------------------------------------------------------- #

def load_report(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def detect_kind(data: dict) -> str:
    """Identify which command produced this JSON. Raises on unknown shapes."""
    rows = data.get("rows")
    if isinstance(rows, list):
        if not rows:
            raise ValueError("harness report has no rows to compare")
        if "leaked" in rows[0]:
            return "injection"
        if "outcome" in rows[0]:
            return "utility"
        raise ValueError("harness report rows have no 'leaked'/'outcome' column")
    if "statistics" in data and "results" in data:
        return "scan"
    raise ValueError(
        "unrecognized report format (expected a `scan`, `injection-scan`, or "
        "`utility-scan` JSON)"
    )


def normalize(data: dict, by: str | None = None) -> NormalizedReport:
    """Reduce a raw report dict to overall + per-group (positives, n) counts."""
    kind = detect_kind(data)

    if kind == "scan":
        stats = data["statistics"]
        n = int(stats.get("total_attacks", 0))
        pos = int(stats.get("hits", 0))
        groups = {
            cat: (int(v["hits"]), int(v["total"]))
            for cat, v in data.get("by_category", {}).items()
        }
        return NormalizedReport(
            kind="scan", label=str(data.get("target", "?")),
            metric_name="Hit rate", lower_is_better=True, group_dim="category",
            overall=(pos, n), groups=groups,
        )

    if kind == "injection":
        field = _INJECTION_GROUP_FIELD.get(by or "probe")
        if field is None:
            raise ValueError(
                f"--by must be one of {sorted(_INJECTION_GROUP_FIELD)} for injection reports"
            )
        meta = data.get("meta", {})
        rows = [r for r in data["rows"] if str(r.get("leaked", "")) != ""]
        pos = sum(1 for r in rows if int(r["leaked"]) == 1)
        groups: dict[str, list[int]] = {}
        for r in rows:
            key = str(r.get(field, "?"))
            g = groups.setdefault(key, [0, 0])
            g[0] += int(r["leaked"]) == 1
            g[1] += 1
        return NormalizedReport(
            kind="injection",
            label=f"{meta.get('backend', '?')}/{meta.get('model', '?')}",
            metric_name="Leak rate", lower_is_better=True,
            group_dim=(by or "probe"),
            overall=(pos, len(rows)),
            groups={k: (v[0], v[1]) for k, v in groups.items()},
        )

    # utility
    by = by or "defense"
    if by not in ("defense", "task"):
        raise ValueError("--by must be 'defense' or 'task' for utility reports")
    meta = data.get("meta", {})
    rows = [r for r in data["rows"] if str(r.get("outcome", "")) != ""]
    pos = sum(1 for r in rows if str(r["outcome"]) == "SUCCESS")
    groups = {}
    for r in rows:
        key = str(r.get(by, "?"))
        g = groups.setdefault(key, [0, 0])
        g[0] += str(r["outcome"]) == "SUCCESS"
        g[1] += 1
    return NormalizedReport(
        kind="utility", label=str(meta.get("model", "?")),
        metric_name="Success rate", lower_is_better=False, group_dim=by,
        overall=(pos, len(rows)),
        groups={k: (v[0], v[1]) for k, v in groups.items()},
    )


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #

def _classify(
    old: tuple[int, int], new: tuple[int, int], lower_is_better: bool
) -> tuple[str, float]:
    """Return (status, p_value) for a change present in both reports."""
    p = two_proportion_pvalue(old[0], old[1], new[0], new[1])
    old_r = old[0] / old[1] if old[1] else 0.0
    new_r = new[0] / new[1] if new[1] else 0.0
    if new_r == old_r:
        return "flat", p
    worse = (new_r > old_r) if lower_is_better else (new_r < old_r)
    if p >= SIG_ALPHA:
        return "flat", p
    return ("regressed" if worse else "improved"), p


def compare(
    old_path: str | Path, new_path: str | Path, by: str | None = None
) -> ComparisonResult:
    """Compare two reports of the same kind and return a structured diff."""
    old = normalize(load_report(old_path), by=by)
    new = normalize(load_report(new_path), by=by)
    if old.kind != new.kind:
        raise ValueError(
            f"cannot compare a `{old.kind}` report against a `{new.kind}` report"
        )

    overall_status, overall_p = _classify(old.overall, new.overall, old.lower_is_better)
    overall = GroupDelta(
        name="overall", old=old.overall, new=new.overall,
        p_value=overall_p, status=overall_status,
    )

    deltas: list[GroupDelta] = []
    for name in sorted(set(old.groups) | set(new.groups)):
        o = old.groups.get(name)
        n = new.groups.get(name)
        if o is not None and n is not None:
            status, p = _classify(o, n, old.lower_is_better)
        elif o is None:
            status, p = "added", 1.0
        else:
            status, p = "removed", 1.0
        deltas.append(GroupDelta(name=name, old=o, new=n, p_value=p, status=status))

    return ComparisonResult(
        kind=old.kind, metric_name=old.metric_name,
        lower_is_better=old.lower_is_better, group_dim=old.group_dim,
        old_label=old.label, new_label=new.label,
        overall=overall, groups=deltas,
    )
