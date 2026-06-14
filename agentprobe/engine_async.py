"""Async Engine — orchestrates parallel scans using asyncio.

Allows running multiple attacks concurrently, dramatically reducing
total time for remote targets.

Features:
  - asyncio.Semaphore for controlled concurrency (default 15)
  - Per-attack error handling (one failure doesn't break the scan)
  - Progress callbacks for real-time monitoring
  - Performance metrics (duration, throughput)
  - Full backward compatibility with synchronous engine
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Literal, Optional

from agentprobe.attacks import Attack, AttackResult, all_attacks
from agentprobe.oracle import judge
from agentprobe.target import Target


@dataclass
class AsyncScanReport:
    """Aggregated result of an async scan with performance metrics.
    
    Fully compatible with synchronous ScanReport but includes timing and throughput data.
    """

    target_name: str
    results: list[AttackResult]
    duration_seconds: float = 0.0  # Total wall-clock time
    concurrent_connections: int = 0  # Semaphore limit used
    errors: list[str] = field(default_factory=list)  # Non-fatal errors during scan

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
    
    @property
    def throughput(self) -> float:
        """Attacks per second."""
        if self.duration_seconds <= 0:
            return 0.0
        return self.total / self.duration_seconds

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


async def run_scan_async(
    target: Target,
    attacks: list[Attack] | None = None,
    categories: set[str] | None = None,
    semaphore_limit: int = 15,
    progress_callback=None,
    oracle_type: Literal["semantic", "legacy"] = "semantic",
    min_confidence: Optional[float] = None,
) -> AsyncScanReport:
    """Run attacks in parallel against target. Returns an AsyncScanReport.
    
    Uses asyncio.Semaphore to control concurrency, preventing connection exhaustion.
    Individual attack failures do not interrupt the scan.

    Args:
        target: AsyncHTTPAgent or any Target instance
        attacks: List of attacks (defaults to all_attacks())
        categories: Filter by category set
        semaphore_limit: Max concurrent connections (default: 15)
        progress_callback: Optional callback(idx, total, attack) called on each completion
        oracle_type: "semantic" (LLM-based) or "legacy" (substring matching)
        min_confidence: Minimum confidence threshold for oracle

    Returns:
        AsyncScanReport with results, metrics, and error log
    """
    import time
    
    start_time = time.time()
    
    attacks = attacks if attacks is not None else all_attacks()
    if categories:
        attacks = [a for a in attacks if a.category in categories]

    results: list[AttackResult] = []
    errors: list[str] = []
    semaphore = asyncio.Semaphore(semaphore_limit)
    
    async def run_one(attack: Attack, idx: int) -> tuple[int, AttackResult]:
        """Run a single attack with semaphore to limit concurrency.
        
        Returns:
            (index, result) tuple for proper ordering
        """
        async with semaphore:
            try:
                target.reset()
                
                # Use async send if available, else fall back to sync
                if hasattr(target, 'send_async'):
                    response = await target.send_async(attack.payload)
                else:
                    # Fallback to sync in thread pool
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None, target.send, attack.payload
                    )
                
                result = judge(
                    attack, response,
                    oracle_type=oracle_type,
                    min_confidence=min_confidence,
                )
                
                if progress_callback:
                    progress_callback(idx, len(attacks), attack)
                    
                return (idx, result)
                
            except Exception as e:
                # Capture error but don't break the scan
                error_msg = f"Attack {attack.id}: {str(e)}"
                errors.append(error_msg)
                
                # Return an ERROR result instead of crashing
                error_result = AttackResult(
                    attack_id=attack.id,
                    success=False,
                    confidence=0.0,
                    evidence="[Error during execution]",
                    payload=attack.payload,
                    response_text=f"Error: {str(e)}",
                    raw_response={"error": str(e)},
                )
                
                if progress_callback:
                    progress_callback(idx, len(attacks), attack)
                    
                return (idx, error_result)

    # Run all attacks concurrently, maintaining order
    result_tuples = await asyncio.gather(
        *[run_one(attack, i) for i, attack in enumerate(attacks, 1)],
        return_exceptions=False,
    )
    
    # Reconstruct results in original order
    for idx, result in result_tuples:
        results.append(result)
    
    duration = time.time() - start_time
    
    return AsyncScanReport(
        target_name=target.name,
        results=results,
        duration_seconds=duration,
        concurrent_connections=semaphore_limit,
        errors=errors,
    )
