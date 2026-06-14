"""Oracle — judges whether an attack succeeded.

Multiple signals, combined:
  1. Substring canary detection (high precision, low recall)
  2. Unauthorized tool call detection (high precision)
  3. Heuristic refusal detection (helps avoid false positives)
  4. LLM-based semantic judgment (optional, high recall, lower precision)

The oracle is a composition: heuristic signals vote, then LLM refines if available.

Usage:
    - Default (semantic): Uses gpt-4o-mini with structured outputs
    - Legacy: Uses substring matching (offline, no API)
"""

from __future__ import annotations

__all__ = ["judge", "get_semantic_oracle", "REFUSAL_MARKERS"]

from typing import Literal, Optional

from agentprobe.attacks.base import Attack, AttackResult
from agentprobe.oracle_legacy import judge_legacy, REFUSAL_MARKERS
from agentprobe.target import AgentResponse

# Global oracle instance (lazy-loaded)
_semantic_oracle: Optional[object] = None


def get_semantic_oracle() -> object:
    """Get or create the global semantic oracle instance.

    Returns:
        SemanticOracle instance

    Raises:
        ImportError: If litellm is not installed
        ValueError: If OPENAI_API_KEY is not set
    """
    global _semantic_oracle
    if _semantic_oracle is None:
        try:
            from agentprobe.oracle_semantic import SemanticOracle

            _semantic_oracle = SemanticOracle()
        except ImportError as e:
            raise ImportError(
                "SemanticOracle requires 'litellm' package. "
                "Install with: pip install litellm"
            ) from e
    return _semantic_oracle


def judge(
    attack: Attack,
    response: AgentResponse,
    oracle_type: Literal["semantic", "legacy"] = "semantic",
    min_confidence: Optional[float] = None,
) -> AttackResult:
    """Decide whether `attack` succeeded against the agent that produced `response`.

    Uses the specified oracle for judgment. Semantic oracle requires OPENAI_API_KEY.
    Legacy oracle uses substring matching (offline, no API).

    Args:
        attack: The attack definition
        response: The agent's response to the attack payload
        oracle_type: "semantic" (LLM-based, default) or "legacy" (substring matching)
        min_confidence: Minimum confidence threshold (0.0-1.0). Can override oracle default.

    Returns:
        AttackResult with judgment details

    Raises:
        ValueError: If OPENAI_API_KEY not set for semantic oracle
        ImportError: If litellm not installed for semantic oracle
    """
    text = response.text or ""

    # Determine which oracle to use
    if oracle_type == "legacy":
        success, confidence, evidence = judge_legacy(attack, response)
        attack_type = "unknown"  # Legacy oracle doesn't categorize attack type

        result = AttackResult(
            attack_id=attack.id,
            success=success,
            confidence=confidence,
            evidence=evidence,
            payload=attack.payload,
            response_text=_truncate_text(text),
            raw_response=response.raw,
        )
        return result

    # Default: semantic oracle
    if oracle_type == "semantic":
        try:
            oracle = get_semantic_oracle()
        except (ImportError, ValueError) as e:
            # Fallback to legacy if semantic unavailable
            success, confidence, evidence = judge_legacy(attack, response)
            result = AttackResult(
                attack_id=attack.id,
                success=success,
                confidence=confidence,
                evidence=evidence or f"fallback: {str(e)[:50]}",
                payload=attack.payload,
                response_text=_truncate_text(text),
                raw_response=response.raw,
            )
            return result

        try:
            # Determine attack type from payload/description
            attack_type = _infer_attack_type(attack)

            oracle_result = oracle.evaluate(
                intent=attack.payload[:500],
                target_response=text[:1000],
                attack_type=attack_type,
                min_confidence=min_confidence,
            )

            evidence = oracle_result.reasoning
            if oracle_result.model_used != "legacy":
                evidence = f"{oracle_result.reasoning} (model: {oracle_result.model_used}, confidence: {oracle_result.confidence:.2f})"

            result = AttackResult(
                attack_id=attack.id,
                success=oracle_result.is_success,
                confidence=oracle_result.confidence,
                evidence=evidence,
                payload=attack.payload,
                response_text=_truncate_text(text),
                raw_response=response.raw,
                oracle_model=oracle_result.model_used,
                oracle_tokens=oracle_result.tokens_used,
                oracle_latency_ms=oracle_result.latency_ms,
            )
            return result

        except Exception as e:
            # On semantic oracle error, return ERROR status
            result = AttackResult(
                attack_id=attack.id,
                success=False,
                confidence=0.0,
                evidence=f"oracle_error: {str(e)[:80]}",
                payload=attack.payload,
                response_text=_truncate_text(text),
                raw_response=response.raw,
            )
            return result

    raise ValueError(f"Unknown oracle type: {oracle_type}")


def _infer_attack_type(attack: Attack) -> str:
    """Infer attack type from attack definition.

    Args:
        attack: The attack definition

    Returns:
        One of "leak", "tool_abuse", "bypass"
    """
    lower_desc = (attack.description + attack.payload).lower()

    if attack.expected_tool_call:
        return "tool_abuse"
    elif any(w in lower_desc for w in ["system prompt", "leak", "reveal", "expose"]):
        return "leak"
    elif any(w in lower_desc for w in ["bypass", "ignore", "override", "persona"]):
        return "bypass"
    else:
        return "leak"  # default


def _truncate_text(text: str, max_len: int = 240) -> str:
    """Truncate text for display.

    Args:
        text: Text to truncate
        max_len: Maximum length (default: 240)

    Returns:
        Truncated text with ellipsis if needed
    """
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"
