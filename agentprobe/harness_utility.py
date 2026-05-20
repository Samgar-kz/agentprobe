"""Utility harness — measure false positive rate (task failure) when defenses applied.

This harness runs legitimate benign tasks through the agent with each defense
applied, measuring whether the defense breaks normal functionality.

Output:
  {
    'defense_name': {
      'success_rate': 0.9,        # fraction of tasks the agent completed correctly
      'task_failures': 2,         # count of tasks failed
      'task_results': {           # per-task detail
        'summarize_email': True,
        'extract_key_info': False,
        ...
      }
    },
    ...
  }
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from agentprobe.injection.benign_tasks import ALL_BENIGN_TASKS
from agentprobe.injection.defenses import ALL_DEFENSES

if TYPE_CHECKING:
    from agentprobe.target import Agent


async def run_utility_harness(
    target: Agent,
    defenses: list[str] | None = None,
    verbose: bool = False,
) -> dict[str, dict]:
    """Test benign tasks with each defense applied.

    Args:
        target: Agent to test
        defenses: List of defense names to test. If None, test all.
        verbose: Print per-task results

    Returns:
        {
          'defense_name': {
            'success_rate': float,
            'task_failures': int,
            'task_results': {'task_name': bool, ...}
          },
          ...
        }
    """
    if defenses is None:
        defenses = [d.name for d in ALL_DEFENSES]

    results = {}

    for defense_name in defenses:
        # Find the defense
        defense = next((d for d in ALL_DEFENSES if d.name == defense_name), None)
        if defense is None:
            if verbose:
                print(f"  ⚠ Defense '{defense_name}' not found, skipping")
            continue

        task_results = {}

        # Run each benign task
        for task in ALL_BENIGN_TASKS:
            try:
                # Send task without any carrier/injection payload
                # The defense should be applied by target when generating prompt
                response = await target.send_async(task.prompt)

                # Check if agent completed the task correctly
                success = task.verify(response)
                task_results[task.name] = success

                if verbose:
                    status = "✓" if success else "✗"
                    print(f"    {status} {task.name} (defense: {defense_name})")

            except Exception as e:
                task_results[task.name] = False
                if verbose:
                    print(f"    ✗ {task.name} (error: {type(e).__name__})")

        # Aggregate results for this defense
        success_count = sum(1 for v in task_results.values() if v)
        total_count = len(task_results)

        results[defense_name] = {
            "success_rate": success_count / total_count if total_count > 0 else 0.0,
            "task_failures": total_count - success_count,
            "task_results": task_results,
        }

    return results


def format_utility_report(harness_results: dict[str, dict]) -> str:
    """Format utility harness results as human-readable table.

    Args:
        harness_results: Output from run_utility_harness()

    Returns:
        Formatted table string
    """
    lines = []
    lines.append("\n=== UTILITY HARNESS RESULTS ===")
    lines.append("(False positive rate: how often defenses break legitimate tasks)\n")

    # Header
    lines.append(f"{'Defense':<20} {'Success Rate':<15} {'Failures':<10}")
    lines.append("-" * 45)

    # Rows
    for defense_name, stats in sorted(harness_results.items()):
        success_rate = stats["success_rate"]
        failures = stats["task_failures"]
        total = len(stats["task_results"])

        rate_str = f"{success_rate * 100:.1f}% ({int(success_rate * total)}/{total})"
        lines.append(f"{defense_name:<20} {rate_str:<15} {failures:<10}")

    lines.append("")
    return "\n".join(lines)
