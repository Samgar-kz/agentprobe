"""HTTPAgent — generic adapter for any HTTP endpoint that takes text and returns text.

Use this when your agent is exposed as a simple JSON API. For OpenAI function-calling
or MCP-style endpoints, write a dedicated adapter that surfaces tool_calls properly.
"""

from __future__ import annotations

from typing import Any

import httpx

from agentprobe.target import AgentResponse, Message, Target


class HTTPAgent(Target):
    """Generic HTTP target. Configure with endpoint + which JSON fields to read/write."""

    name = "http"

    def __init__(
        self,
        endpoint: str,
        input_field: str = "message",
        output_field: str = "reply",
        method: str = "POST",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.endpoint = endpoint
        self.input_field = input_field
        self.output_field = output_field
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def send(self, user_input: str, history: list[Message] | None = None) -> AgentResponse:
        payload: dict[str, Any] = {self.input_field: user_input}
        if history:
            payload["history"] = [{"role": m.role, "content": m.content} for m in history]

        resp = self._client.request(self.method, self.endpoint, headers=self.headers, json=payload)
        resp.raise_for_status()
        data = resp.json()

        text = data.get(self.output_field, "")
        if not isinstance(text, str):
            text = str(text)

        tool_calls = data.get("tool_calls", []) or []

        return AgentResponse(
            text=text, tool_calls=tool_calls, raw=data, status_code=resp.status_code
        )

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "endpoint": self.endpoint, "tools": []}
