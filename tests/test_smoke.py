"""End-to-end smoke test — verifies the scanner finds the bugs we planted in DummyVulnerableAgent.

This test should pass for both v0.1 and v0.2+ implementations.
Version 0.2 may find slightly different attacks due to LLM oracle improvements.
"""

from agentprobe.adapters import DummyVulnerableAgent
from agentprobe.engine import run_scan


def test_scan_finds_vulnerabilities():
    target = DummyVulnerableAgent()
    report, _ = run_scan(target)

    assert report.total > 30, "expected at least 30 attacks in the catalogue"

    # Dummy is intentionally vulnerable; we expect non-trivial hit rate
    assert len(report.hits) >= 5, f"expected ≥5 hits, got {len(report.hits)}"

    # Classic 'direct' attack should be blocked (the dummy refuses literal match)
    direct_results = [r for r in report.results if r.attack_id.startswith("classic.direct")]
    assert direct_results, "classic.direct should exist in catalogue"
    assert not any(r.success for r in direct_results), "classic direct should be blocked by dummy"

    # Pragmatic 'wonder' attack should land — that's the bypass
    wonder = [r for r in report.results if "implicit_wonder" in r.attack_id]
    assert wonder, "implicit_wonder attacks should exist"
    assert any(r.success for r in wonder), "implicit_wonder should bypass the dummy"


def test_by_category_breakdown():
    target = DummyVulnerableAgent()
    report, _ = run_scan(target)
    breakdown = report.by_category()

    for cat in ("pragmatic", "register", "discourse", "codeswitch", "classic"):
        assert cat in breakdown, f"category {cat} missing from breakdown"
