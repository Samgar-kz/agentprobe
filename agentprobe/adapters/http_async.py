"""AsyncHTTPAgent — parallel attack execution via httpx + asyncio.

Enables running multiple attacks concurrently against HTTP endpoints,
dramatically speeding up scans for remote targets.

Features:
  - Async/await for non-blocking concurrent requests
  - Automatic exponential backoff on 429 (rate limit) responses
  - Configurable timeout and max retries
  - Graceful error handling (returns AgentResponse with error details)
  - Optional proxy support via HTTP_PROXY env variable
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

from agentprobe.target import AgentResponse, Message, Target


class AsyncHTTPAgent(Target):
    """Async HTTP target. Same interface as HTTPAgent but with async support.

    Useful for scanning multiple endpoints or running scans in parallel.
    
    Features:
      - Non-blocking concurrent requests via asyncio
      - Automatic exponential backoff on 429 responses
      - Per-request timeout handling
      - Optional proxy support (HTTP_PROXY environment variable)
    """

    name = "http_async"

    def __init__(
        self,
        endpoint: str,
        input_field: str = "message",
        output_field: str = "reply",
        method: str = "POST",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self.endpoint = endpoint
        self.input_field = input_field
        self.output_field = output_field
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Optional proxy support from environment
        self.proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")

    def send(self, user_input: str, history: list[Message] | None = None) -> AgentResponse:
        """Synchronous fallback (for compatibility with base interface)."""
        return asyncio.run(self.send_async(user_input, history))

    async def send_async(
        self, user_input: str, history: list[Message] | None = None
    ) -> AgentResponse:
        """Send a request asynchronously with automatic retry on rate limiting.

        Args:
            user_input: The attack payload
            history: Optional message history

        Returns:
            AgentResponse with text, tool_calls, and raw data
            
        Raises:
            After max_retries exhausted, returns AgentResponse with error details
        """
        payload: dict[str, Any] = {self.input_field: user_input}
        if history:
            payload["history"] = [{"role": m.role, "content": m.content} for m in history]

        # Exponential backoff retry loop for 429 responses
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, proxies=self.proxy) as client:
                    resp = await client.request(
                        self.method, self.endpoint, headers=self.headers, json=payload
                    )
                    
                    # Handle rate limiting with exponential backoff
                    if resp.status_code == 429:
                        if attempt < self.max_retries:
                            backoff = 2 ** attempt  # 1s, 2s, 4s, 8s, ...
                            await asyncio.sleep(backoff)
                            continue
                        else:
                            return AgentResponse(
                                text="",
                                tool_calls=[],
                                raw={"error": "Rate limited after retries", "status": 429},
                            )
                    
                    resp.raise_for_status()
                    data = resp.json()

                    text = data.get(self.output_field, "")
                    if not isinstance(text, str):
                        text = str(text)

                    tool_calls = data.get("tool_calls", []) or []

                    return AgentResponse(text=text, tool_calls=tool_calls, raw=data)
                    
            except asyncio.TimeoutError:
                return AgentResponse(
                    text="",
                    tool_calls=[],
                    raw={"error": f"Request timeout after {self.timeout}s", "status": "timeout"},
                )
            except httpx.HTTPStatusError as e:
                return AgentResponse(
                    text="",
                    tool_calls=[],
                    raw={"error": str(e), "status": e.response.status_code},
                )
            except Exception as e:
                # Graceful degradation for any other error
                return AgentResponse(
                    text="",
                    tool_calls=[],
                    raw={"error": str(e), "status": "error"},
                )
        
        # Should not reach here, but fallback
        return AgentResponse(
            text="",
            tool_calls=[],
            raw={"error": "Unknown error after retries"},
        )

    async def send_batch_async(
        self, payloads: list[str]
    ) -> list[AgentResponse]:
        """Send multiple payloads in parallel.

        Args:
            payloads: List of attack payloads

        Returns:
            List of responses in the same order as payloads
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            tasks = [
                self._send_one(client, payload) for payload in payloads
            ]
            return await asyncio.gather(*tasks)

    async def _send_one(self, client: httpx.AsyncClient, user_input: str) -> AgentResponse:
        """Helper to send a single request with retry logic.
        
        Args:
            client: Reusable httpx.AsyncClient
            user_input: Attack payload
            
        Returns:
            AgentResponse (never raises; errors returned in response.raw)
        """
        payload: dict[str, Any] = {self.input_field: user_input}
        
        # Retry loop with exponential backoff
        for attempt in range(self.max_retries + 1):
            try:
                resp = await client.request(
                    self.method, self.endpoint, headers=self.headers, json=payload
                )
                
                # Handle rate limiting
                if resp.status_code == 429:
                    if attempt < self.max_retries:
                        backoff = 2 ** attempt
                        await asyncio.sleep(backoff)
                        continue
                    else:
                        return AgentResponse(
                            text="",
                            tool_calls=[],
                            raw={"error": "Rate limited after retries", "status": 429},
                        )
                
                resp.raise_for_status()
                data = resp.json()

                text = data.get(self.output_field, "")
                if not isinstance(text, str):
                    text = str(text)

                tool_calls = data.get("tool_calls", []) or []

                return AgentResponse(text=text, tool_calls=tool_calls, raw=data)
                
            except asyncio.TimeoutError:
                return AgentResponse(
                    text="",
                    tool_calls=[],
                    raw={"error": f"Request timeout after {self.timeout}s", "status": "timeout"},
                )
            except httpx.HTTPStatusError as e:
                return AgentResponse(
                    text="",
                    tool_calls=[],
                    raw={"error": str(e), "status": e.response.status_code},
                )
            except Exception as e:
                return AgentResponse(
                    text="",
                    tool_calls=[],
                    raw={"error": str(e), "status": "error"},
                )
        
        return AgentResponse(
            text="",
            tool_calls=[],
            raw={"error": "Unknown error after retries"},
        )

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "endpoint": self.endpoint, "async": True, "tools": []}
