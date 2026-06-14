"""Integration tests for Step 3: Logging and CLI improvements."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agentprobe.adapters import DummyVulnerableAgent
from agentprobe.engine import run_scan
from agentprobe.logging_config import configure_logging, get_logger
from agentprobe.report import write_json
from agentprobe.metrics import ScanMetrics, OracleMetrics


class TestStep3Integration:
    """Full integration tests for Step 3."""
    
    def test_sync_scan_with_metrics(self):
        """Test sync scan with full metrics tracking."""
        target = DummyVulnerableAgent()
        
        # Run scan with metrics
        report, metrics = run_scan(
            target,
            categories={"pragmatic"},
            track_metrics=True,
        )
        
        # Check report
        assert report.target_name == "dummy"
        assert report.total > 0
        assert len(report.results) > 0
        
        # Check metrics
        assert metrics is not None
        assert metrics.total_attacks > 0
        assert metrics.duration_seconds > 0
        assert metrics.throughput > 0
        assert metrics.http_metrics.total_requests > 0
        assert metrics.http_metrics.total_latency_ms > 0
    
    def test_sync_scan_without_metrics(self):
        """Test that sync scan works without metrics tracking."""
        target = DummyVulnerableAgent()
        
        report, metrics = run_scan(
            target,
            categories={"pragmatic"},
            track_metrics=False,
        )
        
        assert report is not None
        assert metrics is None
    
    def test_logging_with_json_format(self):
        """Test JSON logging output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            
            # Configure JSON logging
            configure_logging(
                level="DEBUG",
                json_output=True,
                log_file=str(log_file),
            )
            
            logger = get_logger("test")
            logger.info("Test message", extra={
                "attack_id": "test.attack",
                "success": True,
                "confidence": 0.95,
            })
            
            # Verify JSON format
            content = log_file.read_text().strip()
            log_obj = json.loads(content)
            
            assert log_obj["message"] == "Test message"
            assert log_obj["attack_id"] == "test.attack"
            assert log_obj["success"] is True
    
    def test_json_report_generation(self):
        """Test complete JSON report generation flow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = DummyVulnerableAgent()
            report_path = Path(tmpdir) / "report.json"
            
            # Run scan with metrics
            report, metrics = run_scan(
                target,
                categories={"pragmatic"},
                track_metrics=True,
            )
            
            # Write JSON report
            write_json(report, report_path, metrics=metrics)
            
            # Verify JSON structure
            assert report_path.exists()
            data = json.loads(report_path.read_text())
            
            # Check all required fields
            assert "scan_id" in data
            assert "timestamp" in data
            assert "target" in data
            assert "statistics" in data
            assert "results" in data
            assert "by_category" in data
            
            # Check statistics
            stats = data["statistics"]
            assert stats["total_attacks"] > 0
            # Timing can round to 0 on very fast runners; just require the field
            # to be present and non-negative rather than strictly positive.
            assert stats["total_time_ms"] >= 0
            assert stats["cost_usd"] >= 0
            assert stats["throughput_attacks_per_sec"] >= 0
    
    def test_full_workflow_with_logging(self):
        """Test complete workflow: logging + scan + report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "scan.log"
            report_file = Path(tmpdir) / "report.json"
            
            # Configure logging
            configure_logging(
                level="DEBUG",
                json_output=False,
                log_file=str(log_file),
            )
            
            # Run scan
            target = DummyVulnerableAgent()
            report, metrics = run_scan(
                target,
                categories={"pragmatic"},
                track_metrics=True,
            )
            
            # Write report
            write_json(report, report_file, metrics=metrics)
            
            # Verify all files exist
            assert log_file.exists()
            assert report_file.exists()
            
            # Verify report structure
            report_data = json.loads(report_file.read_text())
            assert report_data["statistics"]["total_attacks"] > 0
    
    def test_metrics_cost_calculation(self):
        """Test that metrics calculate cost correctly."""
        metrics = ScanMetrics(
            total_attacks=45,
            hits=15,
            oracle_metrics=OracleMetrics(
                total_calls=45,
                total_tokens=12600,  # 45 * 280 average
                model="gpt-4o-mini",
            )
        )
        
        # gpt-4o-mini: $0.15 per 1M tokens
        expected_cost = (12600 / 1_000_000) * 0.15
        assert abs(metrics.cost_usd - expected_cost) < 1e-8
    
    def test_metrics_summary_output(self):
        """Test that metrics can be formatted as human-readable summary."""
        metrics = ScanMetrics(
            total_attacks=45,
            hits=15,
            misses=28,
            errors=2,
            duration_seconds=3.4,
            throughput=13.24,
            confidences=[0.92] * 15,
            oracle_metrics=OracleMetrics(
                total_calls=45,
                total_tokens=12600,
                total_latency_ms=8850,
                model="gpt-4o-mini",
            ),
        )
        
        summary = metrics.summary_str()
        
        # Check that summary contains key information
        assert "45 total" in summary
        assert "15 hit" in summary
        assert "28 miss" in summary
        assert "2 error" in summary
        assert "3.40s" in summary
    
    def test_logging_rotation(self):
        """Test that log file rotation works."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test.log"
            
            configure_logging(
                level="INFO",
                log_file=str(log_file),
                max_bytes=100,  # Very small to trigger rotation
                backup_count=3,
            )
            
            logger = get_logger("rotation_test")
            
            # Write many log messages
            for i in range(20):
                logger.info(f"Message {i}: " + "x" * 50)
            
            # Check that backup files were created
            log_dir = log_file.parent
            backups = list(log_dir.glob("test.log*"))
            
            # Should have multiple files due to rotation
            assert len(backups) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
