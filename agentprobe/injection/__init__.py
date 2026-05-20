"""Indirect-injection defensive harness.

Measures whether a tool-agent you own correctly treats tool/data content as
untrusted data rather than as instructions, and compares the effectiveness of
different defenses.
"""

from agentprobe.injection.carriers import ALL_CARRIERS, Carrier
from agentprobe.injection.defenses import ALL_DEFENSES, Defense
from agentprobe.injection.oracle import judge_injection, InjectionResult

__all__ = [
    "ALL_CARRIERS",
    "Carrier",
    "ALL_DEFENSES",
    "Defense",
    "judge_injection",
    "InjectionResult",
]
