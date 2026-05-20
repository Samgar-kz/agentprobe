"""Target adapters — concrete implementations of Target.

HTTPAgent is imported lazily to avoid requiring httpx when only the
in-process dummy is used (useful for tests / minimal installs).
"""

from agentprobe.adapters.dummy import DummyVulnerableAgent

__all__ = ["DummyVulnerableAgent", "HTTPAgent"]


def __getattr__(name):
    if name == "HTTPAgent":
        from agentprobe.adapters.http import HTTPAgent
        return HTTPAgent
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
