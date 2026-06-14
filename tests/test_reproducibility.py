"""Offline tests for the P0 reproducibility layer: `analyze` (recomputes findings
from a committed CSV) and `oracle_validation` (agreement/kappa math).

Fully offline — no API calls. `analyze` is a pure function of the CSV;
`oracle_validation`'s scoring math is tested without invoking the live oracle.
"""

import csv

import pytest

from agentprobe.analyze import GroupRate, analyze_injection
from agentprobe.oracle_validation import OracleValidation, cohens_kappa, format_report

FIELDS = ["defense", "carrier", "channel", "instruction", "category", "leaked", "reason"]


def _row(defense="none", channel="email", probe="p1", leaked=0, carrier="c1"):
    return {
        "defense": defense, "carrier": carrier, "channel": channel,
        "instruction": probe, "category": "leak", "leaked": leaked, "reason": "",
    }


def _rows(channel, leaks, n, defense="none", probe="p1"):
    return [_row(defense=defense, channel=channel, probe=probe, leaked=1 if i < leaks else 0)
            for i in range(n)]


def _write(tmp_path, rows, fields=FIELDS, name="scan.csv"):
    p = tmp_path / name
    with open(p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return str(p)


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #

def test_overall_and_channel_counts(tmp_path):
    res = analyze_injection(_write(tmp_path, _rows("email", 20, 100) + _rows("memory", 40, 100)))
    assert (res.total.leaks, res.total.n) == (60, 200)
    ch = {g.name: (g.leaks, g.n) for g in res.by_channel}
    assert ch["email"] == (20, 100)
    assert ch["memory"] == (40, 100)


def test_channel_significance_vs_email(tmp_path):
    # 40% memory vs 20% email at N=100 each is significant.
    res = analyze_injection(_write(tmp_path, _rows("email", 20, 100) + _rows("memory", 40, 100)))
    assert res.channel_vs_email["memory"] < 0.05
    assert "email" not in res.channel_vs_email  # baseline isn't compared to itself


def test_error_rows_excluded(tmp_path):
    rows = _rows("email", 5, 95) + [_row(channel="email", leaked="")] * 5
    res = analyze_injection(_write(tmp_path, rows))
    assert res.total.n == 95  # the 5 error rows don't count


def test_channel_display_order(tmp_path):
    rows = _rows("memory", 1, 10) + _rows("email", 1, 10) + _rows("webpage", 1, 10)
    names = [g.name for g in analyze_injection(_write(tmp_path, rows)).by_channel]
    assert names.index("email") < names.index("webpage") < names.index("memory")


def test_by_defense_and_probe(tmp_path):
    rows = (_rows("email", 30, 100, defense="none", probe="pa")
            + _rows("email", 2, 100, defense="spotlight", probe="pb"))
    res = analyze_injection(_write(tmp_path, rows))
    d = {g.name: g.rate for g in res.by_defense}
    assert d["none"] > d["spotlight"]
    assert {"pa", "pb"} <= {g.name for g in res.by_probe}


def test_grouprate_rate_and_ci():
    g = GroupRate("x", 2, 100)
    assert g.rate == 0.02
    p, lo, hi = g.ci
    assert lo < 0.02 < hi


def test_not_injection_csv_raises(tmp_path):
    p = _write(tmp_path, [{"model": "m", "defense": "none", "outcome": "SUCCESS"}],
               fields=["model", "defense", "outcome"], name="util.csv")
    with pytest.raises(ValueError):
        analyze_injection(p)


def test_empty_csv_raises(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("")
    with pytest.raises(ValueError):
        analyze_injection(str(p))


# --------------------------------------------------------------------------- #
# oracle_validation (math only — no live oracle call)
# --------------------------------------------------------------------------- #

def test_cohens_kappa_perfect_agreement():
    assert cohens_kappa(10, 0, 10, 0) == 1.0


def test_cohens_kappa_no_agreement_beyond_chance():
    # All predicted leak; gold split evenly -> kappa ~ 0.
    assert abs(cohens_kappa(5, 5, 0, 0)) < 1e-9


def test_oracle_validation_agreement_and_report():
    v = OracleValidation(
        n=24, model="gpt-4o-mini", min_confidence=0.0,
        tp=11, fp=1, tn=10, fn=2,
        disagreements=[
            ({"id": "x", "label": 1, "note": "missed leak"}, False, 0.3),
            ({"id": "y", "label": 0, "note": "warned about link"}, True, 0.6),
        ],
    )
    assert v.agreement == pytest.approx(21 / 24)  # 87.5%
    assert 0 < v.kappa < 1
    report = format_report(v)
    assert "Agreement" in report
    assert "kappa" in report.lower()
    assert "FALSE NEGATIVE" in report  # fn=2 surfaced
