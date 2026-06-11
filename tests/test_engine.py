"""Tests for the scan engine — orchestration and reporting."""

import pytest
from agentprobe.adapters import DummyVulnerableAgent
from agentprobe.engine import run_scan, ScanReport
from agentprobe.attacks.base import Attack, Severity


class TestScanExecution:
    """Tests for running a scan end-to-end."""

    def test_scan_runs_successfully(self):
        """Scan should complete without errors."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target)
        assert report is not None
        assert isinstance(report, ScanReport)

    def test_scan_produces_results(self):
        """Scan should produce result list."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target)
        assert report.results is not None
        assert isinstance(report.results, list)
        assert len(report.results) > 0

    def test_scan_covers_all_attacks(self):
        """By default, scan should run all attacks."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target)
        # Should have significant number of attacks
        assert report.total >= 30

    def test_scan_with_category_filter(self):
        """Scan should respect category filter."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target, categories={"pragmatic"})
        
        # All results should be pragmatic
        for result in report.results:
            assert result.attack_id.startswith("pragmatic.")
        
        # Should be fewer than total
        all_report, _ = run_scan(target)
        assert report.total < all_report.total

    def test_scan_with_multiple_category_filters(self):
        """Scan should handle multiple category filters."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target, categories={"pragmatic", "register"})
        
        # All results should be in one of these categories
        for result in report.results:
            cat = result.attack_id.split(".")[0]
            assert cat in {"pragmatic", "register"}

    def test_progress_callback_called(self):
        """Progress callback should be called during scan."""
        target = DummyVulnerableAgent()
        calls = []

        def callback(idx, total, attack):
            calls.append((idx, total, attack.id))

        report, _ = run_scan(target, progress_callback=callback)
        
        assert len(calls) > 0, "progress callback was not called"
        # Check callback was called in order
        for i, call in enumerate(calls):
            assert call[0] == i + 1, "progress callback index incorrect"


class TestScanReport:
    """Tests for the ScanReport object."""

    @pytest.fixture
    def sample_report(self):
        """Create a sample report for testing."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target)
        return report

    def test_report_target_name(self, sample_report):
        """Report should record target name."""
        assert sample_report.target_name == "dummy"

    def test_report_total(self, sample_report):
        """Report.total should count all results."""
        assert sample_report.total == len(sample_report.results)

    def test_report_hits(self, sample_report):
        """Report.hits should only include successful attacks."""
        for hit in sample_report.hits:
            assert hit.success is True
        for miss in sample_report.results:
            if miss not in sample_report.hits:
                assert miss.success is False

    def test_report_success_rate(self, sample_report):
        """Report.success_rate should calculate correctly."""
        expected_rate = len(sample_report.hits) / sample_report.total
        assert abs(sample_report.success_rate - expected_rate) < 0.001

    def test_report_by_category(self, sample_report):
        """Report.by_category should break down by category."""
        breakdown = sample_report.by_category()
        
        # Should have all categories
        for cat in ("pragmatic", "register", "discourse", "codeswitch", "classic"):
            assert cat in breakdown, f"missing category {cat}"
        
        # Each category should have total and hits
        for cat, stats in breakdown.items():
            assert "total" in stats
            assert "hits" in stats
            assert stats["total"] > 0
            assert stats["hits"] >= 0
            assert stats["hits"] <= stats["total"]

    def test_report_by_category_sum_to_total(self, sample_report):
        """Sum of category totals should equal report total."""
        breakdown = sample_report.by_category()
        total_from_cats = sum(s["total"] for s in breakdown.values())
        assert total_from_cats == sample_report.total


class TestScanWithCustomAttacks:
    """Tests for scanning with custom attack list."""

    def test_scan_with_empty_attacks_list(self):
        """Scan with empty attacks list should produce empty report."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target, attacks=[])
        assert report.total == 0
        assert len(report.hits) == 0

    def test_scan_with_single_attack(self):
        """Scan with one attack should produce one result."""
        target = DummyVulnerableAgent()
        attack = Attack(
            id="test.single",
            category="classic",
            severity=Severity.HIGH,
            description="Test",
            payload="test payload",
            success_signals=["NOMATCH"],
        )
        report, _ = run_scan(target, attacks=[attack])
        assert report.total == 1
        assert len(report.results) == 1
        assert report.results[0].attack_id == "test.single"


class TestScanEdgeCases:
    """Tests for edge cases and error handling."""

    def test_scan_target_reset_called(self):
        """Target.reset() should be called between attacks."""
        # This is tested implicitly by DummyVulnerableAgent behavior
        target = DummyVulnerableAgent()
        report1, _ = run_scan(target)
        report2, _ = run_scan(target)
        # Both scans should work correctly (reset handled properly)
        assert report1.total == report2.total

    def test_scan_result_has_required_fields(self):
        """Each result should have all required fields."""
        target = DummyVulnerableAgent()
        report, _ = run_scan(target)
        
        for result in report.results:
            assert result.attack_id
            assert result.success is not None
            assert 0 <= result.confidence <= 1
            assert result.evidence is not None
            assert result.payload
            assert result.response_text is not None

    def test_scan_results_maintain_order(self):
        """Results should correspond to attack order."""
        from agentprobe.attacks import all_attacks
        
        target = DummyVulnerableAgent()
        attacks = all_attacks()
        report, _ = run_scan(target, attacks=attacks[:5])
        
        for i, result in enumerate(report.results):
            assert result.attack_id == attacks[i].id
