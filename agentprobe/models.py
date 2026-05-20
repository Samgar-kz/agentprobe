"""Shared data models for AgentProbe."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class OracleResult:
    """Result of oracle judgment (semantic or legacy)."""

    is_success: bool
    is_refusal: bool
    confidence: float  # 0.0 to 1.0
    attack_type: str  # "leak" | "tool_abuse" | "bypass" | "unknown"
    reasoning: str
    model_used: str = "legacy"
    tokens_used: int = 0
    latency_ms: float = 0.0
