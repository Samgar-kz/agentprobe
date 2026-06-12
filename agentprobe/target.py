"""Target — abstract interface to anything we want to attack."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Message:
    """One turn in a conversation with an agent."""

    role: str  # "user" | "assistant" | "tool"
    content: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AgentResponse:
    """What we got back from the target after sending input."""

    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    # HTTP status code for transport-backed targets; None for in-process agents.
    status_code: Optional[int] = None


class Target(ABC):
    """Abstract target. Implement this to plug a new agent into the scanner."""

    name: str = "abstract"

    @abstractmethod
    def send(self, user_input: str, history: list[Message] | None = None) -> AgentResponse:
        """Send `user_input` to the agent and return its response."""
        raise NotImplementedError

    def reset(self) -> None:
        """Optional: reset agent state between attacks. Default: no-op."""
        return None

    def describe(self) -> dict[str, Any]:
        """Optional: tell the scanner what tools the agent has, for smarter attacks."""
        return {"name": self.name, "tools": []}
