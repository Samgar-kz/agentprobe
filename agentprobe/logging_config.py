"""Structured logging configuration for AgentProbe.

Supports both human-readable console output and machine-readable JSON.
Includes rotation-safe file logging with configurable sizes and backups.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import datetime
from typing import Any, Optional


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        """Convert LogRecord to JSON."""
        log_obj: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "attack_id"):
            log_obj["attack_id"] = record.attack_id
        if hasattr(record, "target"):
            log_obj["target"] = record.target
        if hasattr(record, "success"):
            log_obj["success"] = record.success
        if hasattr(record, "confidence"):
            log_obj["confidence"] = record.confidence
        if hasattr(record, "latency_ms"):
            log_obj["latency_ms"] = record.latency_ms
        if hasattr(record, "tokens"):
            log_obj["tokens"] = record.tokens
        if hasattr(record, "cost"):
            log_obj["cost"] = record.cost
        if hasattr(record, "http_status"):
            log_obj["http_status"] = record.http_status
        if hasattr(record, "retry_attempt"):
            log_obj["retry_attempt"] = record.retry_attempt

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
) -> None:
    """Configure logging for AgentProbe.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_output: Whether to output JSON format
        log_file: Optional file to write logs to (with rotation)
        max_bytes: Max size per log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
    """
    root = logging.getLogger("agentprobe")
    root.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root.handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    if json_output:
        console_handler.setFormatter(JSONFormatter())
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # File handler with rotation (optional)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        if json_output:
            file_handler.setFormatter(JSONFormatter())
        else:
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
            )
            file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given name."""
    return logging.getLogger(f"agentprobe.{name}")
