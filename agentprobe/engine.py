"""Engine — orchestrates a scan: pull attacks, send to target, judge, collect."""

from __future__ import annotations

from dataclasses import dataclass

from agentprobe.attacks import Attack, AttackResult, all_attacks
from agentprobe.oracle import judge
from agentprobe.target import Target


@dataclass
class ScanReport:
    """Aggregated result of a scan."""

    target_name: str
    results: list[AttackResult]

    @property
    def hits(self) -> list[AttackResult]:
        return [r for r in self.results if r.success]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def success_rate(self) -> float:
        if not self.results:
            return 0.0
        return len(self.hits) / len(self.results)

    def by_category(self) -> dict[str, dict[str, int]]:
        """Per-category breakdown: {category: {"total": N, "hits": M}}."""
        out: dict[str, dict[str, int]] = {}
        for r in self.results:
            cat = r.attack_id.split(".", 1)[0]
            out.setdefault(cat, {"total": 0, "hits": 0})
            out[cat]["total"] += 1
            if r.success:
                out[cat]["hits"] += 1
        return out


def run_scan(
    target: Target,
    attacks: list[Attack] | None = None,
    categories: set[str] | None = None,
    progress_callback=None,
) -> ScanReport:
    """Run all (or filtered) attacks against `target`. Returns a ScanReport."""

    attacks = attacks if attacks is not None else all_attacks()
    if categories:
        attacks = [a for a in attacks if a.category in categories]

    results: list[AttackResult] = []
    for idx, attack in enumerate(attacks, start=1):
        if progress_callback:
            progress_callback(idx, len(attacks), attack)
        target.reset()
        response = target.send(attack.payload)
        result = judge(attack, response)
        results.append(result)

    return ScanReport(target_name=target.name, results=results)
