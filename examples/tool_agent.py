"""Back-compat shim. ToolAgent now lives in the installed package so the harness
is reproducible from `pip install agentprobe-injection` without a repo clone.

Prefer importing from the package directly:

    from agentprobe.injection.tool_agent import ToolAgent
"""

from agentprobe.injection.tool_agent import (  # noqa: F401
    SYSTEM_PROMPT,
    TOOLS,
    ToolAgent,
)

__all__ = ["ToolAgent", "SYSTEM_PROMPT", "TOOLS"]
