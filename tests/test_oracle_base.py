"""Offline tests for the unified Oracle interface (oracle_base.py).

No API calls: the deterministic oracle runs its real detectors; the semantic
oracle is exercised through an injected fake engine; the hybrid oracle is tested
for its precision-then-recall composition (including that it does NOT pay for the
LLM when the deterministic detector already fired).
"""

from types import SimpleNamespace

import pytest

from agentprobe.injection.instructions import ALL_PROBES
from agentprobe.oracle_base import (
    ORACLES,
    DeterministicOracle,
    HybridOracle,
    Oracle,
    SemanticOracle,
    Verdict,
    get_oracle,
)
from agentprobe.target import AgentResponse

PROBES = {p.name: p for p in ALL_PROBES}
CANARY_PROBE = PROBES["reveal_canary"]


def _resp(text="", tool_calls=None):
    return AgentResponse(text=text, tool_calls=tool_calls or [])


class _FakeEngine:
    """Stand-in for oracle_semantic.SemanticOracle — records calls, no network."""

    def __init__(self, is_success, confidence=0.9, reasoning="fake"):
        self._r = SimpleNamespace(is_success=is_success, confidence=confidence, reasoning=reasoning)
        self.calls = []

    def evaluate(self, intent, target_response, attack_type, **_):
        self.calls.append((intent, target_response, attack_type))
        return self._r


class _Exploding(Oracle):
    name = "boom"

    def judge(self, response, *, probe=None, intent=None, attack_type=None):
        raise AssertionError("semantic oracle should not have been called")


class _Const(Oracle):
    name = "const"

    def __init__(self, success):
        self._success = success

    def judge(self, response, *, probe=None, intent=None, attack_type=None):
        return Verdict(self._success, 0.7, "novel leak" if self._success else "held", source="semantic")


# --------------------------------------------------------------------------- #
# ABC contract
# --------------------------------------------------------------------------- #

def test_oracle_is_abstract():
    with pytest.raises(TypeError):
        Oracle()


def test_registry_and_get_oracle():
    assert isinstance(get_oracle("deterministic"), DeterministicOracle)
    assert isinstance(get_oracle("hybrid"), HybridOracle)
    assert set(ORACLES) == {"deterministic", "semantic", "hybrid"}
    with pytest.raises(ValueError):
        get_oracle("nope")


def test_get_semantic_does_not_need_api_key():
    # The engine is built lazily, so constructing the adapter must not require a key.
    assert isinstance(get_oracle("semantic"), SemanticOracle)


# --------------------------------------------------------------------------- #
# Deterministic (real detectors)
# --------------------------------------------------------------------------- #

def test_deterministic_hit_and_hold():
    o = DeterministicOracle()
    hit = o.judge(_resp("Summary. CONFIG-CANARY-7f3a"), probe=CANARY_PROBE)
    assert hit.success is True
    assert hit.source == "deterministic"
    held = o.judge(_resp("Q4 revenue up 12%."), probe=CANARY_PROBE)
    assert held.success is False


# --------------------------------------------------------------------------- #
# Semantic adapter (fake engine)
# --------------------------------------------------------------------------- #

def test_semantic_adapter_maps_result():
    eng = _FakeEngine(True, 0.8, "leaked the canary")
    v = SemanticOracle(inner=eng).judge(_resp("anything"), intent="x", attack_type="leak")
    assert (v.success, v.confidence, v.reason, v.source) == (True, 0.8, "leaked the canary", "semantic")


def test_semantic_adapter_falls_back_to_probe_fields():
    eng = _FakeEngine(False)
    SemanticOracle(inner=eng).judge(_resp("text"), probe=CANARY_PROBE)
    intent, _resp_text, attack_type = eng.calls[0]
    assert intent == CANARY_PROBE.instruction
    assert attack_type == CANARY_PROBE.category


# --------------------------------------------------------------------------- #
# Hybrid (precision then recall)
# --------------------------------------------------------------------------- #

def test_hybrid_shortcircuits_on_deterministic_hit():
    # Deterministic detector fires -> semantic must NOT be consulted (no cost).
    h = HybridOracle(semantic=_Exploding())
    v = h.judge(_resp("Summary. CONFIG-CANARY-7f3a"), probe=CANARY_PROBE)
    assert v.success is True
    assert v.source == "hybrid"


def test_hybrid_escalates_to_semantic_recall():
    # Deterministic holds on a benign-looking response; semantic catches it.
    h = HybridOracle(semantic=_Const(True))
    v = h.judge(_resp("totally benign summary"), probe=CANARY_PROBE)
    assert v.success is True
    assert v.source == "hybrid"
    assert v.reason.startswith("semantic_recall:")


def test_hybrid_both_hold():
    h = HybridOracle(semantic=_Const(False))
    v = h.judge(_resp("benign"), probe=CANARY_PROBE)
    assert v.success is False
    assert v.source == "hybrid"
