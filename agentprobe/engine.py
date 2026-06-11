"""Engine — orchestrates a scan: pull attacks, send to target, judge, collect.

Includes:
- Attack orchestration (sync mode)
- Oracle integration with logging
- Metrics tracking (timing, tokens, cost)
- Progress callbacks for real-time monitoring
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal, Optional

from agentprobe.attacks import Attack, AttackResult, all_attacks
from agentprobe.oracle import judge
from agentprobe.target import Target
from agentprobe.logging_config import get_logger
from agentprobe.metrics import ScanMetrics, OracleMetrics

logger = get_logger("engine")


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
    oracle_type: Literal["semantic", "legacy"] = "semantic",
    min_confidence: Optional[float] = None,
    track_metrics: bool = True,
) -> tuple[ScanReport, Optional[ScanMetrics]]:
    """Run all (or filtered) attacks against `target`. Returns a ScanReport and optional metrics.

    Args:
        target: Target agent to scan
        attacks: Override attack list (default: all_attacks())
        categories: Filter by category set
        progress_callback: Optional callback(idx, total, attack) for progress
        oracle_type: "semantic" (LLM-based) or "legacy" (substring matching)
        min_confidence: Minimum confidence threshold for oracle
        track_metrics: Whether to track detailed metrics (timing, tokens, cost)

    Returns:
        Tuple of (ScanReport, Optional[ScanMetrics])
    """

    attacks = attacks if attacks is not None else all_attacks()
    if categories:
        attacks = [a for a in attacks if a.category in categories]

    start_time = time.time()
    results: list[AttackResult] = []
    metrics = ScanMetrics(total_attacks=len(attacks)) if track_metrics else None
    
    for idx, attack in enumerate(attacks, start=1):
        if progress_callback:
            progress_callback(idx, len(attacks), attack)
        
        target.reset()
        
        # Track HTTP timing if available
        http_start = time.time()
        response = target.send(attack.payload)
        http_latency_ms = (time.time() - http_start) * 1000
        
        if metrics:
            metrics.http_metrics.total_requests += 1
            metrics.http_metrics.total_latency_ms += http_latency_ms
            if hasattr(response, "status_code"):
                status = response.status_code
                metrics.http_metrics.status_codes[status] = metrics.http_metrics.status_codes.get(status, 0) + 1
        
        # Judge the result
        result = judge(attack, response, oracle_type=oracle_type, min_confidence=min_confidence)
        results.append(result)
        
        # Track metrics
        if metrics:
            if result.success:
                metrics.hits += 1
                metrics.confidences.append(result.confidence)
            else:
                if result.confidence > 0:
                    metrics.misses += 1
                else:
                    metrics.errors += 1

            # Aggregate oracle (LLM) call cost/latency. Only LLM-based oracles
            # populate oracle_tokens/model; the offline legacy oracle reports 0.
            if result.oracle_model and result.oracle_model != "legacy":
                metrics.oracle_metrics.total_calls += 1
                metrics.oracle_metrics.total_tokens += result.oracle_tokens
                metrics.oracle_metrics.total_latency_ms += result.oracle_latency_ms
                metrics.oracle_metrics.model = result.oracle_model
        
        # Log the attack result
        logger.debug(
            f"Attack {attack.id} executed",
            extra={
                "attack_id": attack.id,
                "success": result.success,
                "confidence": result.confidence,
                "latency_ms": http_latency_ms,
            }
        )
    
    duration = time.time() - start_time
    
    if metrics:
        metrics.duration_seconds = duration
        metrics.throughput = len(attacks) / duration if duration > 0 else 0.0
        if metrics.confidences:
            metrics.avg_confidence = sum(metrics.confidences) / len(metrics.confidences)
    
    logger.info(
        f"Scan completed: {len([r for r in results if r.success])} hits / {len(results)} attacks",
        extra={
            "total_attacks": len(results),
            "hits": len([r for r in results if r.success]),
            "duration_seconds": duration,
        }
    )
    
    return ScanReport(target_name=target.name, results=results), metrics
