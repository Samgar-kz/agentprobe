"""Unit tests for the regression-comparison engine (`agentprobe compare`).

Fully offline: synthetic report dicts are written to tmp files and compared. The
key behaviors under test are (1) format auto-detection, (2) correct
positive/negative semantics per report kind, and (3) that a change is only called
improved/regressed when it is statistically significant — noise stays flat.
"""

import json

import pytest

from agentprobe.compare import compare, detect_kind, normalize, trend
from agentprobe.metrics import two_proportion_pvalue


# --------------------------------------------------------------------------- #
# Synthetic report builders
# --------------------------------------------------------------------------- #

def inj_row(defense, probe, leaked, carrier="email_basic", category="leak"):
    return {
        "defense": defense, "carrier": carrier, "channel": "email",
        "instruction": probe, "category": category,
        "leaked": leaked, "reason": probe if leaked == 1 else "held",
    }


def probe_rows(probe, pos, n, defense="none"):
    """`pos` leaked rows and `n - pos` held rows for one probe."""
    return [inj_row(defense, probe, 1 if i < pos else 0) for i in range(n)]


def inj_report(rows, backend="openai", model="gpt-4o-mini"):
    return {"meta": {"backend": backend, "model": model, "repeats": 5}, "rows": rows}


def util_row(defense, outcome, task="t1"):
    return {
        "model": "m", "defense": defense, "task": task,
        "task_id": "benign_001", "iteration": 0, "outcome": outcome,
    }


def util_rows(defense, success, n):
    return [util_row(defense, "SUCCESS" if i < success else "FAIL") for i in range(n)]


def util_report(rows, model="gpt-4o-mini"):
    return {"meta": {"model": model}, "rows": rows}


def scan_report(hits=10, total=100, cats=None):
    return {
        "scan_id": "x", "timestamp": "t", "target": "dummy",
        "statistics": {
            "total_attacks": total, "hits": hits, "misses": total - hits,
            "errors": 0, "avg_confidence": 0.9,
        },
        "by_category": cats or {"classic": {"hits": hits, "total": total}},
        "results": [],
    }


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------- #
# Format detection
# --------------------------------------------------------------------------- #

def test_detect_injection():
    assert detect_kind(inj_report(probe_rows("p", 1, 5))) == "injection"


def test_detect_utility():
    assert detect_kind(util_report(util_rows("none", 3, 5))) == "utility"


def test_detect_scan():
    assert detect_kind(scan_report()) == "scan"


def test_detect_unknown_raises():
    with pytest.raises(ValueError):
        detect_kind({"foo": 1})


def test_detect_empty_rows_raises():
    with pytest.raises(ValueError):
        detect_kind({"rows": []})


# --------------------------------------------------------------------------- #
# Statistics helper
# --------------------------------------------------------------------------- #

def test_two_proportion_identical_is_one():
    assert two_proportion_pvalue(50, 100, 50, 100) == 1.0


def test_two_proportion_large_diff_significant():
    assert two_proportion_pvalue(5, 100, 50, 100) < 0.001


def test_two_proportion_undefined_is_one():
    assert two_proportion_pvalue(0, 0, 5, 10) == 1.0
    assert two_proportion_pvalue(0, 100, 0, 100) == 1.0  # zero variance


# --------------------------------------------------------------------------- #
# Injection comparison
# --------------------------------------------------------------------------- #

def test_injection_regression_improvement_and_noise(tmp_path):
    old = inj_report(
        probe_rows("improver", 50, 400)
        + probe_rows("regressor", 5, 400)
        + probe_rows("steady", 10, 400)
    )
    new = inj_report(
        probe_rows("improver", 5, 400)
        + probe_rows("regressor", 50, 400)
        + probe_rows("steady", 12, 400)
    )
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))

    assert res.kind == "injection"
    assert res.metric_name == "Leak rate"
    assert res.group_dim == "probe"
    status = {g.name: g.status for g in res.groups}
    assert status["improver"] == "improved"
    assert status["regressor"] == "regressed"
    assert status["steady"] == "flat"
    assert res.has_regression is True  # the regressor gates CI


def test_injection_no_regression(tmp_path):
    old = inj_report(probe_rows("p1", 50, 400) + probe_rows("p2", 40, 400))
    new = inj_report(probe_rows("p1", 5, 400) + probe_rows("p2", 38, 400))
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert res.has_regression is False
    assert {g.name for g in res.improved} == {"p1"}


def test_injection_group_by_defense(tmp_path):
    rows = probe_rows("p1", 30, 200, defense="none") + probe_rows("p1", 5, 200, defense="spotlight")
    res = compare(
        _write(tmp_path, "a.json", inj_report(rows)),
        _write(tmp_path, "b.json", inj_report(rows)),
        by="defense",
    )
    assert res.group_dim == "defense"
    assert {"none", "spotlight"} <= {g.name for g in res.groups}


def test_injection_bad_by_raises(tmp_path):
    p = _write(tmp_path, "a.json", inj_report(probe_rows("p", 1, 10)))
    with pytest.raises(ValueError):
        compare(p, p, by="nonsense")


def test_added_and_removed_groups_do_not_gate(tmp_path):
    old = inj_report(probe_rows("p1", 10, 100))
    new = inj_report(probe_rows("p1", 10, 100) + probe_rows("p2_new", 5, 100))
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert {g.name for g in res.added} == {"p2_new"}
    assert res.has_regression is False  # coverage change, not a regression


def test_error_rows_excluded(tmp_path):
    # A row with leaked="" is an error and must not count toward N.
    rows = probe_rows("p1", 5, 95) + [inj_row("none", "p1", "")] * 5
    rep = normalize(inj_report(rows))
    assert rep.overall == (5, 95)


# --------------------------------------------------------------------------- #
# Utility comparison (higher is better — inverted semantics)
# --------------------------------------------------------------------------- #

def test_utility_success_drop_is_regression(tmp_path):
    old = util_report(util_rows("none", 95, 100))
    new = util_report(util_rows("none", 50, 100))
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert res.lower_is_better is False
    assert res.metric_name == "Success rate"
    assert res.overall.status == "regressed"
    assert res.has_regression is True


def test_utility_success_rise_is_improvement(tmp_path):
    old = util_report(util_rows("none", 50, 100))
    new = util_report(util_rows("none", 95, 100))
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert res.overall.status == "improved"
    assert res.has_regression is False


# --------------------------------------------------------------------------- #
# Scan (engine) comparison
# --------------------------------------------------------------------------- #

def test_scan_improvement(tmp_path):
    old = scan_report(hits=40, total=100, cats={"classic": {"hits": 40, "total": 100}})
    new = scan_report(hits=10, total=100, cats={"classic": {"hits": 10, "total": 100}})
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert res.kind == "scan"
    assert res.metric_name == "Hit rate"
    assert res.overall.status == "improved"
    assert res.has_regression is False


def test_scan_overall_regression_gates(tmp_path):
    old = scan_report(hits=10, total=200, cats={"classic": {"hits": 10, "total": 200}})
    new = scan_report(hits=60, total=200, cats={"classic": {"hits": 60, "total": 200}})
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert res.overall.status == "regressed"
    assert res.has_regression is True


# --------------------------------------------------------------------------- #
# Incompatible / missing
# --------------------------------------------------------------------------- #

def test_incompatible_kinds_raise(tmp_path):
    inj = _write(tmp_path, "i.json", inj_report(probe_rows("p", 1, 10)))
    scan = _write(tmp_path, "s.json", scan_report())
    with pytest.raises(ValueError):
        compare(inj, scan)


def test_delta_pp_and_rates(tmp_path):
    old = inj_report(probe_rows("p1", 20, 100))
    new = inj_report(probe_rows("p1", 5, 100))
    res = compare(_write(tmp_path, "a.json", old), _write(tmp_path, "b.json", new))
    assert res.overall.old_rate == pytest.approx(0.20)
    assert res.overall.new_rate == pytest.approx(0.05)
    assert res.overall.delta_pp == pytest.approx(-15.0)


# --------------------------------------------------------------------------- #
# trend (series over N reports)
# --------------------------------------------------------------------------- #

def test_trend_flags_step_regression(tmp_path):
    a = _write(tmp_path, "a.json", inj_report(probe_rows("p1", 10, 400)))
    b = _write(tmp_path, "b.json", inj_report(probe_rows("p1", 12, 400)))  # ~flat vs a
    c = _write(tmp_path, "c.json", inj_report(probe_rows("p1", 60, 400)))  # jump vs b
    res = trend([a, b, c])
    statuses = [p.status for p in res.points]
    assert statuses[0] == "baseline"
    assert statuses[2] == "regressed"
    assert res.has_regression is True


def test_trend_improvement_no_regression(tmp_path):
    a = _write(tmp_path, "a.json", inj_report(probe_rows("p1", 60, 400)))
    b = _write(tmp_path, "b.json", inj_report(probe_rows("p1", 5, 400)))
    res = trend([a, b])
    assert res.points[1].status == "improved"
    assert res.has_regression is False


def test_trend_needs_two_reports(tmp_path):
    a = _write(tmp_path, "a.json", inj_report(probe_rows("p1", 1, 10)))
    with pytest.raises(ValueError):
        trend([a])


def test_trend_mixed_kinds_raise(tmp_path):
    inj = _write(tmp_path, "i.json", inj_report(probe_rows("p", 1, 10)))
    scan = _write(tmp_path, "s.json", scan_report())
    with pytest.raises(ValueError):
        trend([inj, scan])
