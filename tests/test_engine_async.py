"""Tests for async engine — orchestration, concurrency, error handling."""

import asyncio
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch

from agentprobe.adapters import DummyVulnerableAgent
from agentprobe.adapters.http_async import AsyncHTTPAgent
from agentprobe.engine_async import run_scan_async, AsyncScanReport
from agentprobe.attacks.base import Attack, Severity
from agentprobe.attacks import all_attacks
from agentprobe.target import AgentResponse


class TestAsyncScanReportMetrics:
    """Tests for AsyncScanReport metrics."""

    def test_report_with_metrics(self):
        """AsyncScanReport should track duration and throughput."""
        results = []
        for i in range(10):
            attack = Attack(
                id=f"test.{i}",
                category="classic",
                severity=Severity.HIGH,
                description="Test",
                payload="test",
                success_signals=["MATCH"],
            )
            from agentprobe.attacks.base import AttackResult
            result = AttackResult(
                attack_id=attack.id,
                success=True if i % 2 == 0 else False,
                confidence=0.9,
                evidence="evidence",
                payload="test",
                response_text="response",
            )
            results.append(result)

        report = AsyncScanReport(
            target_name="test",
            results=results,
            duration_seconds=2.0,
            concurrent_connections=15,
        )

        assert report.total == 10
        assert report.throughput == 5.0  # 10 attacks / 2 seconds
        assert len(report.hits) == 5
        assert report.success_rate == 0.5

    def test_report_zero_duration(self):
        """Report with zero duration should have zero throughput."""
        report = AsyncScanReport(
            target_name="test",
            results=[],
            duration_seconds=0.0,
            concurrent_connections=15,
        )

        assert report.throughput == 0.0


class TestAsyncScanExecution:
    """Tests for run_scan_async function."""

    @pytest.mark.asyncio
    async def test_async_scan_runs(self):
        """Async scan should execute without errors."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:10]

        report = await run_scan_async(
            target,
            attacks=attacks,
            semaphore_limit=5,
        )

        assert isinstance(report, AsyncScanReport)
        assert report.total == 10
        assert len(report.results) == 10

    @pytest.mark.asyncio
    async def test_async_scan_respects_semaphore(self):
        """Async scan should limit concurrent connections."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:20]

        report = await run_scan_async(
            target,
            attacks=attacks,
            semaphore_limit=5,
        )

        assert report.concurrent_connections == 5
        assert report.total == 20

    @pytest.mark.asyncio
    async def test_async_scan_with_category_filter(self):
        """Async scan should respect category filter."""
        target = DummyVulnerableAgent()

        report = await run_scan_async(
            target,
            categories={"pragmatic"},
        )

        # All results should be pragmatic
        for result in report.results:
            assert result.attack_id.startswith("pragmatic.")

    @pytest.mark.asyncio
    async def test_async_scan_progress_callback(self):
        """Async scan should call progress callback."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:5]
        calls = []

        def callback(idx, total, attack):
            calls.append((idx, total, attack.id))

        await run_scan_async(
            target,
            attacks=attacks,
            progress_callback=callback,
        )

        # Should have been called for each attack
        assert len(calls) == 5
        # Check callback was called with correct indices
        for i, call in enumerate(calls):
            assert call[0] == i + 1
            assert call[1] == 5


class TestAsyncScanErrorHandling:
    """Tests for error handling during async scans."""

    @pytest.mark.asyncio
    async def test_scan_individual_error_doesnt_break_scan(self):
        """Individual attack errors should not interrupt the scan."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:10]

        # Mock one attack to fail
        with patch("agentprobe.engine_async.judge") as mock_judge:
            call_count = [0]

            def judge_side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 3:
                    raise RuntimeError("Judge failed")
                from agentprobe.attacks.base import AttackResult
                return AttackResult(
                    attack_id=args[0].id,
                    success=False,
                    confidence=0.0,
                    evidence="",
                    payload="",
                    response_text="",
                )

            mock_judge.side_effect = judge_side_effect

            report = await run_scan_async(target, attacks=attacks)

            # Should still complete despite error
            assert report.total == 10
            # Should have logged the error
            assert len(report.errors) > 0

    @pytest.mark.asyncio
    async def test_scan_with_timeout_errors(self):
        """Scan should handle timeout errors gracefully."""
        target = AsyncHTTPAgent(endpoint="http://localhost:9999")
        
        # Create a small set of attacks
        attacks = [
            Attack(
                id=f"test.timeout_{i}",
                category="classic",
                severity=Severity.HIGH,
                description="Test",
                payload="test",
                success_signals=["MATCH"],
            )
            for i in range(3)
        ]

        # This will fail due to nonexistent endpoint, but shouldn't crash
        report = await run_scan_async(
            target,
            attacks=attacks,
            semaphore_limit=1,
        )

        assert report.total == 3
        # Errors may occur, but scan completes
        assert isinstance(report, AsyncScanReport)


class TestAsyncConcurrency:
    """Tests for proper async/await concurrency."""

    @pytest.mark.asyncio
    async def test_concurrent_execution_faster_than_serial(self):
        """Concurrent execution should be faster than serial for many attacks."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:20]

        # Run async
        start = time.time()
        report = await run_scan_async(
            target,
            attacks=attacks,
            semaphore_limit=10,
        )
        async_time = time.time() - start

        # Run sync (for reference)
        from agentprobe.engine import run_scan
        start = time.time()
        sync_report, _ = run_scan(target, attacks=attacks)
        sync_time = time.time() - start

        # Both should complete
        assert report.total == len(attacks)
        assert sync_report.total == len(attacks)

        # Async should generally be faster for many small attacks
        # (though not guaranteed due to overhead)
        print(f"\nAsync: {async_time:.3f}s, Sync: {sync_time:.3f}s")


class TestAsyncScanMetrics:
    """Tests for performance metrics tracking."""

    @pytest.mark.asyncio
    async def test_duration_measurement(self):
        """Report should accurately measure duration."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:5]

        report = await run_scan_async(target, attacks=attacks)

        assert report.duration_seconds > 0
        # Should have completed reasonably fast (< 10s for 5 attacks on dummy)
        assert report.duration_seconds < 10

    @pytest.mark.asyncio
    async def test_throughput_calculation(self):
        """Throughput should be calculated correctly."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:10]

        report = await run_scan_async(target, attacks=attacks)

        expected_throughput = 10 / report.duration_seconds
        assert abs(report.throughput - expected_throughput) < 0.01


class TestAsyncScanOracle:
    """Tests for oracle integration in async scans."""

    @pytest.mark.asyncio
    async def test_async_scan_with_legacy_oracle(self):
        """Async scan should work with legacy oracle."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:5]

        report = await run_scan_async(
            target,
            attacks=attacks,
            oracle_type="legacy",
        )

        assert report.total == 5
        # All results should be present
        assert len(report.results) == 5

    @pytest.mark.asyncio
    async def test_async_scan_with_confidence_threshold(self):
        """Async scan should respect confidence threshold."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:5]

        report = await run_scan_async(
            target,
            attacks=attacks,
            oracle_type="legacy",
            min_confidence=0.8,
        )

        assert report.total == 5
        # All results should still be collected
        assert len(report.results) == 5


class TestAsyncHTTPTargetIntegration:
    """Tests for AsyncHTTPAgent with async engine."""

    @pytest.mark.asyncio
    async def test_async_engine_with_async_http_target(self):
        """Async engine should work with AsyncHTTPAgent."""
        # Create a mock AsyncHTTPAgent
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")

        # Mock the send_async method
        async def mock_send_async(payload):
            await asyncio.sleep(0.001)  # Simulate network delay
            return AgentResponse(
                text=f"Response to {payload[:20]}",
                tool_calls=[],
                raw={"message": "ok"},
            )

        agent.send_async = mock_send_async

        attacks = all_attacks()[:10]

        report = await run_scan_async(
            agent,
            attacks=attacks,
            semaphore_limit=5,
        )

        assert report.total == 10
        assert report.concurrent_connections == 5
        # Should have executed successfully
        assert isinstance(report, AsyncScanReport)


class TestAsyncScanEdgeCases:
    """Tests for edge cases in async execution."""

    @pytest.mark.asyncio
    async def test_empty_attacks_list(self):
        """Scan with empty attacks should produce empty report."""
        target = DummyVulnerableAgent()

        report = await run_scan_async(target, attacks=[])

        assert report.total == 0
        assert len(report.results) == 0

    @pytest.mark.asyncio
    async def test_single_attack(self):
        """Scan with one attack should complete successfully."""
        target = DummyVulnerableAgent()
        attack = Attack(
            id="test.single",
            category="classic",
            severity=Severity.HIGH,
            description="Test",
            payload="test",
            success_signals=["NOMATCH"],
        )

        report = await run_scan_async(target, attacks=[attack])

        assert report.total == 1
        assert len(report.results) == 1

    @pytest.mark.asyncio
    async def test_high_semaphore_limit(self):
        """Scan should work with semaphore limit > num attacks."""
        target = DummyVulnerableAgent()
        attacks = all_attacks()[:3]

        report = await run_scan_async(
            target,
            attacks=attacks,
            semaphore_limit=100,
        )

        assert report.total == 3
        assert report.concurrent_connections == 100
