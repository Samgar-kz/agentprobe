"""Tests for AsyncHTTPAgent — async HTTP adapter with exponential backoff."""

import asyncio
import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from agentprobe.adapters.http_async import AsyncHTTPAgent
from agentprobe.target import AgentResponse


class TestAsyncHTTPAgentInit:
    """Tests for AsyncHTTPAgent initialization."""

    def test_init_with_defaults(self):
        """AsyncHTTPAgent should use sensible defaults."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")
        assert agent.endpoint == "http://localhost:8000"
        assert agent.input_field == "message"
        assert agent.output_field == "reply"
        assert agent.timeout == 30.0
        assert agent.max_retries == 3

    def test_init_with_custom_fields(self):
        """AsyncHTTPAgent should accept custom field names."""
        agent = AsyncHTTPAgent(
            endpoint="http://localhost:8000",
            input_field="query",
            output_field="result",
        )
        assert agent.input_field == "query"
        assert agent.output_field == "result"

    def test_init_with_custom_timeout(self):
        """AsyncHTTPAgent should accept custom timeout."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000", timeout=60.0)
        assert agent.timeout == 60.0

    def test_init_with_custom_retries(self):
        """AsyncHTTPAgent should accept custom max_retries."""
        agent = AsyncHTTPAgent(
            endpoint="http://localhost:8000",
            max_retries=5,
        )
        assert agent.max_retries == 5

    def test_init_with_custom_headers(self):
        """AsyncHTTPAgent should accept custom headers."""
        headers = {"Authorization": "Bearer token123"}
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000", headers=headers)
        assert "Authorization" in agent.headers
        assert agent.headers["Authorization"] == "Bearer token123"


class TestAsyncHTTPAgentSend:
    """Tests for send_async method (mock-based, no real HTTP)."""

    @pytest.mark.asyncio
    async def test_send_async_success(self):
        """send_async should return AgentResponse on 200 OK."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"reply": "Hello, world!"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.return_value = mock_response
            mock_client_class.return_value = mock_client

            response = await agent.send_async("test payload")

            assert isinstance(response, AgentResponse)
            assert response.text == "Hello, world!"
            assert isinstance(response.tool_calls, list)
            assert response.raw == {"reply": "Hello, world!"}

    @pytest.mark.asyncio
    async def test_send_async_with_tool_calls(self):
        """send_async should extract tool_calls from response."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "reply": "Using a tool",
            "tool_calls": [{"name": "get_weather", "args": {"location": "NYC"}}],
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.return_value = mock_response
            mock_client_class.return_value = mock_client

            response = await agent.send_async("get weather")

            assert len(response.tool_calls) == 1
            assert response.tool_calls[0]["name"] == "get_weather"

    @pytest.mark.asyncio
    async def test_send_async_timeout(self):
        """send_async should handle timeout gracefully."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000", timeout=1.0)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.side_effect = asyncio.TimeoutError()
            mock_client_class.return_value = mock_client

            response = await agent.send_async("test")

            assert response.text == ""
            assert "timeout" in response.raw.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_send_async_http_error(self):
        """send_async should handle HTTP errors gracefully."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server error", request=MagicMock(), response=mock_response
        )

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.return_value = mock_response
            mock_client_class.return_value = mock_client

            response = await agent.send_async("test")

            assert response.text == ""
            assert response.raw.get("status") == 500


class TestAsyncHTTPAgentRateLimiting:
    """Tests for exponential backoff on 429 responses."""

    @pytest.mark.asyncio
    async def test_429_retry_success(self):
        """send_async should retry on 429 and succeed on second attempt."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000", max_retries=3)

        # First call returns 429, second returns 200
        mock_response_429 = MagicMock()
        mock_response_429.status_code = 429

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {"reply": "Success after retry"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.side_effect = [mock_response_429, mock_response_200]
            mock_client_class.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                response = await agent.send_async("test")

                assert response.text == "Success after retry"
                # Verify sleep was called (exponential backoff)
                mock_sleep.assert_called_once()

    @pytest.mark.asyncio
    async def test_429_exhausted_retries(self):
        """send_async should fail gracefully after max retries."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000", max_retries=2)

        # Always return 429
        mock_response = MagicMock()
        mock_response.status_code = 429

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.return_value = mock_response
            mock_client_class.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                response = await agent.send_async("test")

                assert response.text == ""
                assert "rate limited" in response.raw.get("error", "").lower()
                assert response.raw.get("status") == 429

    @pytest.mark.asyncio
    async def test_exponential_backoff_timing(self):
        """send_async should use exponential backoff: 1s, 2s, 4s, ..."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000", max_retries=3)

        # Return 429 three times, then 200
        responses = [
            MagicMock(status_code=429),
            MagicMock(status_code=429),
            MagicMock(status_code=429),
            MagicMock(status_code=200, json=lambda: {"reply": "ok"}),
        ]

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.side_effect = responses
            mock_client_class.return_value = mock_client

            sleep_calls = []

            async def mock_sleep(duration):
                sleep_calls.append(duration)

            with patch("asyncio.sleep", side_effect=mock_sleep):
                response = await agent.send_async("test")

                assert response.text == "ok"
                # Should have called sleep with 1s, 2s, 4s
                assert sleep_calls == [1, 2, 4]


class TestAsyncHTTPAgentBatch:
    """Tests for send_batch_async method."""

    @pytest.mark.asyncio
    async def test_send_batch_async_success(self):
        """send_batch_async should send multiple payloads concurrently."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")

        mock_response = MagicMock()
        mock_response.status_code = 200

        responses = [
            MagicMock(status_code=200, json=lambda: {"reply": f"response_{i}"})
            for i in range(3)
        ]

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.request.side_effect = responses
            mock_client_class.return_value = mock_client

            payloads = ["payload_0", "payload_1", "payload_2"]
            results = await agent.send_batch_async(payloads)

            assert len(results) == 3
            assert all(isinstance(r, AgentResponse) for r in results)

    @pytest.mark.asyncio
    async def test_send_batch_async_partial_failure(self):
        """send_batch_async should handle partial failures gracefully."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")

        responses = [
            MagicMock(status_code=200, json=lambda: {"reply": "ok"}),
            MagicMock(status_code=500),  # Will fail
            MagicMock(status_code=200, json=lambda: {"reply": "ok"}),
        ]

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None

            async def side_effect(*args, **kwargs):
                if not responses:
                    return responses.pop(0)
                return responses.pop(0)

            mock_client.request.side_effect = responses
            mock_client_class.return_value = mock_client

            payloads = ["a", "b", "c"]
            # This test verifies the method handles errors in the batch
            results = await agent.send_batch_async(payloads)

            assert len(results) == 3


class TestAsyncHTTPAgentDescribe:
    """Tests for describe method."""

    def test_describe_includes_async_flag(self):
        """describe should include async=True."""
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000")
        desc = agent.describe()

        assert desc["name"] == "http_async"
        assert desc["async"] is True
        assert "endpoint" in desc


class TestAsyncHTTPAgentIntegration:
    """Integration test (would require a real server)."""

    @pytest.mark.skip(reason="Requires running HTTP server")
    @pytest.mark.asyncio
    async def test_real_http_request(self):
        """Integration test with actual HTTP endpoint."""
        # This would require a test server running
        agent = AsyncHTTPAgent(endpoint="http://localhost:8000/chat")
        response = await agent.send_async("hello")
        assert isinstance(response, AgentResponse)
