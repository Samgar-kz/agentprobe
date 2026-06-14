"""Tests for logging configuration and structured logging."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

import pytest

from agentprobe.logging_config import configure_logging, get_logger, JSONFormatter


def test_configure_logging_console():
    """Test basic console logging configuration."""
    configure_logging(level="INFO")
    logger = get_logger("test")
    assert logger.level == logging.INFO or logger.getEffectiveLevel() == logging.INFO


def test_configure_logging_debug():
    """Test debug logging configuration."""
    configure_logging(level="DEBUG")
    logger = get_logger("test")
    assert logger.getEffectiveLevel() == logging.DEBUG


def test_configure_logging_file():
    """Test file logging with rotation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"
        configure_logging(level="INFO", log_file=str(log_file))
        logger = get_logger("test")
        
        logger.info("Test message")
        
        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message" in content


def test_json_logging():
    """Test JSON format logging."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"
        configure_logging(level="INFO", json_output=True, log_file=str(log_file))
        logger = get_logger("test_json")
        
        logger.info("Test JSON", extra={"attack_id": "test.attack", "confidence": 0.95})
        
        content = log_file.read_text().strip()
        log_obj = json.loads(content)
        
        assert log_obj["message"] == "Test JSON"
        assert log_obj["level"] == "INFO"
        assert log_obj["attack_id"] == "test.attack"
        assert log_obj["confidence"] == 0.95


def test_json_formatter_with_fields():
    """Test JSONFormatter with various extra fields."""
    formatter = JSONFormatter()
    
    # Create a log record with extra fields
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    record.attack_id = "test.attack"
    record.success = True
    record.confidence = 0.85
    record.latency_ms = 150.5
    record.tokens = 280
    record.cost = 0.00003
    record.http_status = 200
    record.retry_attempt = 2
    
    formatted = formatter.format(record)
    log_obj = json.loads(formatted)
    
    assert log_obj["message"] == "Test message"
    assert log_obj["attack_id"] == "test.attack"
    assert log_obj["success"] is True
    assert log_obj["confidence"] == 0.85
    assert log_obj["latency_ms"] == 150.5
    assert log_obj["tokens"] == 280
    assert log_obj["cost"] == 0.00003
    assert log_obj["http_status"] == 200
    assert log_obj["retry_attempt"] == 2


def test_logger_naming():
    """Test that loggers are named correctly."""
    logger1 = get_logger("engine")
    logger2 = get_logger("oracle")
    
    assert logger1.name == "agentprobe.engine"
    assert logger2.name == "agentprobe.oracle"


def test_file_rotation():
    """Test that log files rotate when they exceed max size."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"
        
        # Configure with small max_bytes to trigger rotation
        configure_logging(
            level="INFO",
            log_file=str(log_file),
            max_bytes=100,  # Very small
            backup_count=3,
        )
        logger = get_logger("rotation_test")
        
        # Write enough messages to trigger rotation
        for i in range(10):
            logger.info(f"Test message {i}: " + "x" * 50)
        
        # Check that backup files were created
        log_dir = log_file.parent
        backups = list(log_dir.glob("test.log*"))
        assert len(backups) >= 2  # At least main + one backup


def test_logging_extra_fields():
    """Test logging with extra fields for structured data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"
        configure_logging(level="DEBUG", json_output=True, log_file=str(log_file))
        logger = get_logger("structured")
        
        logger.info(
            "Attack executed",
            extra={
                "attack_id": "pragmatic.leak_system_prompt",
                "success": True,
                "confidence": 0.92,
                "latency_ms": 1850,
                "tokens": 280,
            }
        )
        
        content = log_file.read_text().strip()
        log_obj = json.loads(content)
        
        assert log_obj["attack_id"] == "pragmatic.leak_system_prompt"
        assert log_obj["success"] is True
        assert log_obj["latency_ms"] == 1850
        assert log_obj["tokens"] == 280


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
