"""Unified Oracle interface.

The project grew two judging philosophies, with different call shapes:

  * deterministic per-probe detectors — `injection/oracle.py:judge_injection(
    response, probe)` — high precision, the basis of the headline injection numbers;
  * an LLM-as-judge — `oracle_semantic.SemanticOracle.evaluate(intent,
    target_response, attack_type)` — higher recall, used by the generic scan path.

This module unifies them behind one `Oracle.judge(response, ...)` returning a
common `Verdict`, and adds `HybridOracle` — deterministic precision *plus*
semantic recall, a combination neither path offers alone. The existing engines
are kept and wrapped, so this is an additive interface layer, not a rewrite.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from agentprobe.target import AgentResponse


@dataclass
class Verdict:
    """A single oracle judgment, uniform across deterministic and semantic oracles."""

    success: bool          # did the injection/attack succeed (a leak)?
    confidence: float
    reason: str
    evidence: str = ""
    source: str = ""       # which oracle produced this verdict


class Oracle(ABC):
    """Judges whether an agent response shows a successful injection/attack.

    Context is passed by keyword so every implementation accepts the same call:
    deterministic oracles use `probe`; semantic oracles use `intent`/`attack_type`
    (and fall back to the probe's fields when only a probe is given).
    """

    name: str = "oracle"

    @abstractmethod
    def judge(
        self,
        response: AgentResponse,
        *,
        probe: Any = None,
        intent: Optional[str] = None,
        attack_type: Optional[str] = None,
    ) -> Verdict:
        ...


class DeterministicOracle(Oracle):
    """Per-probe substring / tool-call detectors. No model call; exact and free."""

    name = "deterministic"

    def judge(self, response, *, probe=None, intent=None, attack_type=None) -> Verdict:
        from agentprobe.injection.oracle import judge_injection

        r = judge_injection(response, probe=probe)
        return Verdict(r.leaked, r.confidence, r.reason, r.evidence, source=self.name)


class SemanticOracle(Oracle):
    """LLM-as-judge. Adapter over `oracle_semantic.SemanticOracle` (the engine).

    Pass a pre-built engine via `inner` (used in tests); otherwise one is created
    lazily on first use, so importing this module never requires an API key.
    """

    name = "semantic"

    def __init__(self, inner: Any = None, **engine_kwargs: Any):
        self._inner = inner
        self._engine_kwargs = engine_kwargs

    @property
    def inner(self) -> Any:
        if self._inner is None:
            from agentprobe.oracle_semantic import SemanticOracle as _SemanticEngine

            self._inner = _SemanticEngine(**self._engine_kwargs)
        return self._inner

    def judge(self, response, *, probe=None, intent=None, attack_type=None) -> Verdict:
        text = getattr(response, "text", None) or ""
        if intent is None and probe is not None:
            intent = getattr(probe, "instruction", "")
        if attack_type is None and probe is not None:
            attack_type = getattr(probe, "category", "leak")
        res = self.inner.evaluate(
            intent=intent or "",
            target_response=text,
            attack_type=attack_type or "leak",
        )
        return Verdict(
            bool(res.is_success), float(res.confidence), res.reasoning, source=self.name
        )


class HybridOracle(Oracle):
    """Deterministic first, then semantic for recall.

    A deterministic positive is trusted as-is (high precision, and free — no model
    call). Only a deterministic *held* is escalated to the LLM judge, which can
    catch leaks the fixed detector patterns miss. This is the combination neither
    oracle offers alone.
    """

    name = "hybrid"

    def __init__(self, deterministic: Oracle = None, semantic: Oracle = None):
        self.deterministic = deterministic or DeterministicOracle()
        self._semantic = semantic

    @property
    def semantic(self) -> Oracle:
        if self._semantic is None:
            self._semantic = SemanticOracle()
        return self._semantic

    def judge(self, response, *, probe=None, intent=None, attack_type=None) -> Verdict:
        d = self.deterministic.judge(response, probe=probe)
        if d.success:
            return Verdict(True, d.confidence, d.reason, d.evidence, source=self.name)
        s = self.semantic.judge(response, probe=probe, intent=intent, attack_type=attack_type)
        if s.success:
            return Verdict(True, s.confidence, f"semantic_recall:{s.reason}", s.evidence, source=self.name)
        return Verdict(False, d.confidence, d.reason, d.evidence, source=self.name)


# Registry for selecting an oracle by name (e.g. a future --oracle flag).
ORACLES = {
    DeterministicOracle.name: DeterministicOracle,
    SemanticOracle.name: SemanticOracle,
    HybridOracle.name: HybridOracle,
}


def get_oracle(name: str, **kwargs: Any) -> Oracle:
    """Build an oracle by name: 'deterministic' | 'semantic' | 'hybrid'."""
    if name not in ORACLES:
        raise ValueError(f"Unknown oracle '{name}'. Choose one of {sorted(ORACLES)}.")
    return ORACLES[name](**kwargs)
