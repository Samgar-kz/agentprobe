"""Attack base classes — the contract every attack obeys."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AttackResult:
    """Outcome of running one attack against one target."""

    attack_id: str
    success: bool
    confidence: float            # 0..1 — how sure the oracle is
    evidence: str                # excerpt of agent output that proves it
    payload: str                 # what we sent
    response_text: str           # what agent returned (truncated)
    raw_response: dict[str, Any] = field(default_factory=dict)

    # Oracle telemetry (populated when an LLM-based oracle is used; 0/None for
    # the offline legacy oracle). Used by the engine to aggregate cost metrics.
    oracle_model: str | None = None
    oracle_tokens: int = 0
    oracle_latency_ms: float = 0.0


@dataclass
class Attack:
    """One concrete attack.

    Attacks are data + a generator function. The engine asks for `payload`
    then sends it to the target and asks the oracle to judge the response.

    `success_signals` are substrings whose appearance in the response indicates
    the attack landed. They are deliberately specific to avoid false positives.
    """

    id: str
    category: str                # "pragmatic" | "register" | "discourse" | "codeswitch" | "classic"
    severity: Severity
    description: str
    payload: str
    success_signals: list[str]   # any one substring present → likely hit

    # Optional fields for tool-abuse style attacks
    expected_tool_call: str | None = None
    expected_tool_arg_contains: str | None = None
