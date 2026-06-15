"""CallableTarget — wrap any Python callable as a scan target.

The 80/20 framework adapter: instead of maintaining brittle adapters for every
agent framework (LangChain / LlamaIndex / CrewAI, whose APIs churn), you hand
AgentProbe a function `fn(prompt: str) -> str` and it scans your agent
in-process — no HTTP server needed.

    from agentprobe.adapters import CallableTarget
    from agentprobe.engine import run_scan

    def my_agent(prompt: str) -> str:
        return my_chain.invoke(prompt)          # LangChain / LlamaIndex / CrewAI / ...

    report = run_scan(CallableTarget(my_agent), attacks)

The callable may return a plain string, a dict (`{"text": ..., "tool_calls": [...]}`),
or an `AgentResponse` for full control — return tool calls so tool-abuse detectors
can see them.
"""

from __future__ import annotations

from typing import Any, Callable

from agentprobe.target import AgentResponse, Target


def _coerce(result: Any) -> AgentResponse:
    """Normalize whatever the user's callable returned into an AgentResponse."""
    if isinstance(result, AgentResponse):
        return result
    if isinstance(result, str):
        return AgentResponse(text=result)
    if isinstance(result, dict):
        return AgentResponse(
            text=str(result.get("text", "")),
            tool_calls=list(result.get("tool_calls", []) or []),
            raw=result,
        )
    return AgentResponse(text=str(result))


class CallableTarget(Target):
    """Adapt a Python callable `fn(prompt: str) -> str | dict | AgentResponse`."""

    name = "callable"

    def __init__(
        self,
        fn: Callable[[str], Any],
        name: str | None = None,
        tools: list | None = None,
        reset: Callable[[], None] | None = None,
    ):
        if not callable(fn):
            raise TypeError("CallableTarget requires a callable fn(prompt: str) -> str")
        self._fn = fn
        self.name = name or getattr(fn, "__name__", "callable")
        self._tools = tools or []
        self._reset = reset

    def send(self, user_input, history=None) -> AgentResponse:
        return _coerce(self._fn(user_input))

    def reset(self) -> None:
        if self._reset is not None:
            self._reset()

    def describe(self) -> dict:
        return {"name": self.name, "tools": self._tools}
