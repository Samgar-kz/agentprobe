"""Tests for CallableTarget — wrapping a Python callable as a scan target."""

import pytest

from agentprobe.adapters import CallableTarget
from agentprobe.adapters.callable import _coerce
from agentprobe.target import AgentResponse


def test_string_return_becomes_response():
    r = CallableTarget(lambda p: f"echo: {p}").send("hi")
    assert isinstance(r, AgentResponse)
    assert r.text == "echo: hi"


def test_dict_return_with_tool_calls():
    def fn(p):
        return {"text": "done", "tool_calls": [{"name": "send_email", "args": {"to": "x@y.z"}}]}
    r = CallableTarget(fn).send("go")
    assert r.text == "done"
    assert r.tool_calls[0]["name"] == "send_email"
    assert r.raw["text"] == "done"


def test_agentresponse_passes_through():
    resp = AgentResponse(text="t", tool_calls=[{"name": "f", "args": {}}])
    assert CallableTarget(lambda p: resp).send("x") is resp


def test_non_callable_raises():
    with pytest.raises(TypeError):
        CallableTarget(123)


def test_name_defaults_to_fn_name_or_override():
    def my_agent(p):
        return p
    assert CallableTarget(my_agent).name == "my_agent"
    assert CallableTarget(my_agent, name="custom").name == "custom"


def test_describe_and_reset_hook():
    calls = []
    t = CallableTarget(lambda p: "ok", name="a", tools=["search"], reset=lambda: calls.append(1))
    assert t.describe() == {"name": "a", "tools": ["search"]}
    t.reset()
    assert calls == [1]


def test_coerce_fallback_stringifies():
    assert _coerce(42).text == "42"


def test_end_to_end_with_oracle():
    # A leaky callable agent (echoes the canary) is caught via the deterministic oracle.
    from agentprobe.injection.instructions import ALL_PROBES
    from agentprobe.injection.oracle import judge_injection

    probe = {p.name: p for p in ALL_PROBES}["reveal_canary"]
    t = CallableTarget(lambda p: "Here you go: CONFIG-CANARY-7f3a")
    assert judge_injection(t.send("summarize"), probe=probe).leaked is True
