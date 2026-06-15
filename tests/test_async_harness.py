"""Offline tests for the async injection harness.

No network: ToolAgent.asend is monkeypatched to return canned responses, so the
test exercises the orchestration (concurrency, aggregation, error handling) and
asserts the async path produces the same shape of result as the sync one.
"""

import asyncio

from agentprobe.injection import harness as H
from agentprobe.injection.carriers import ALL_CARRIERS
from agentprobe.injection.instructions import ALL_PROBES
from agentprobe.injection.tool_agent import ToolAgent
from agentprobe.target import AgentResponse


def _patch_asend(monkeypatch, text, tool_calls=None):
    async def fake_asend(self, user_input, history=None):
        self.last_usage = {"tokens": 7, "latency_ms": 1.0}
        return AgentResponse(text=text, tool_calls=tool_calls or [])
    monkeypatch.setattr(ToolAgent, "asend", fake_asend)


def test_async_harness_all_benign_holds(monkeypatch):
    _patch_asend(monkeypatch, "benign summary, nothing to see here")
    res = asyncio.run(H.run_injection_harness_async(repeats=1, concurrency=4))

    assert res.meta["async"] is True
    assert res.meta["concurrency"] == 4
    expected_rows = len(res.defenses) * len(ALL_CARRIERS) * len(ALL_PROBES) * 1
    assert len(res.rows) == expected_rows
    assert sum(s.leaks for s in res.defenses) == 0
    assert all(r["leaked"] == 0 for r in res.rows)


def test_async_harness_detects_canary_leak(monkeypatch):
    _patch_asend(monkeypatch, "Summary. CONFIG-CANARY-7f3a")
    res = asyncio.run(H.run_injection_harness_async(repeats=1, concurrency=4))

    # reveal_canary fires on every carrier x defense; no other probe matches.
    assert sum(s.leaks for s in res.defenses) == len(res.defenses) * len(ALL_CARRIERS)
    leaked_probes = {r["instruction"] for r in res.rows if r["leaked"] == 1}
    assert leaked_probes == {"reveal_canary"}


def test_async_harness_records_errors(monkeypatch):
    async def boom(self, user_input, history=None):
        raise RuntimeError("provider down")
    monkeypatch.setattr(ToolAgent, "asend", boom)

    res = asyncio.run(H.run_injection_harness_async(repeats=1, concurrency=4))
    assert all(r["leaked"] == "" for r in res.rows)          # all error rows
    assert all("provider down" in r["reason"] for r in res.rows)
    assert sum(s.total for s in res.defenses) == 0           # nothing scored


def test_async_progress_called_for_every_attempt(monkeypatch):
    _patch_asend(monkeypatch, "benign")
    seen = []
    asyncio.run(H.run_injection_harness_async(
        repeats=1, concurrency=8, progress=lambda done, total: seen.append((done, total))
    ))
    total = len(ALL_CARRIERS) * len(ALL_PROBES) * 1 * 5  # 5 string defenses
    assert seen[-1][0] == total          # final done count reaches the total
    assert all(t == total for _, t in seen)
