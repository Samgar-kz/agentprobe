"""Performance metrics and cost tracking for AgentProbe scans.

Tracks:
- Total attacks run, hits/misses/errors
- HTTP request/response times
- Oracle call tokens and latencies
- Cost estimation based on token usage
- Throughput (attacks/sec) for async mode
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Model pricing (per 1M tokens)
MODEL_PRICING = {
    "gpt-4o-mini": 0.15,       # $0.15 per 1M input tokens
    "gpt-4o": 5.0,              # $5 per 1M input tokens
    "claude-3-haiku": 0.80,     # $0.80 per 1M input tokens
    "gemini-1.5-flash": 0.075,  # $0.075 per 1M input tokens
}


@dataclass
class OracleMetrics:
    """Metrics for oracle calls (LLM-based judgments)."""
    
    total_calls: int = 0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    model: str = "gpt-4o-mini"
    
    @property
    def avg_latency_ms(self) -> float:
        """Average latency per oracle call."""
        if self.total_calls == 0:
            return 0.0
        return self.total_latency_ms / self.total_calls
    
    @property
    def cost_usd(self) -> float:
        """Estimated cost in USD based on tokens and model pricing."""
        price_per_1m = MODEL_PRICING.get(self.model, 0.15)  # default: gpt-4o-mini
        return (self.total_tokens / 1_000_000) * price_per_1m


@dataclass
class HTTPMetrics:
    """Metrics for HTTP adapter requests."""
    
    total_requests: int = 0
    total_latency_ms: float = 0.0
    errors: int = 0
    status_codes: dict[int, int] = field(default_factory=dict)
    
    @property
    def avg_latency_ms(self) -> float:
        """Average latency per request."""
        if self.total_requests == 0:
            return 0.0
        return self.total_latency_ms / self.total_requests
    
    @property
    def success_rate(self) -> float:
        """Percentage of successful requests (200-299)."""
        if self.total_requests == 0:
            return 1.0
        successful = sum(count for code, count in self.status_codes.items() if 200 <= code < 300)
        return successful / self.total_requests


@dataclass
class ScanMetrics:
    """Comprehensive metrics for a complete scan."""
    
    total_attacks: int
    hits: int = 0
    misses: int = 0
    errors: int = 0
    
    # Timing
    duration_seconds: float = 0.0
    throughput: float = 0.0  # attacks/sec
    
    # Sub-metrics
    oracle_metrics: OracleMetrics = field(default_factory=OracleMetrics)
    http_metrics: HTTPMetrics = field(default_factory=HTTPMetrics)
    
    # Confidence tracking
    avg_confidence: float = 0.0
    confidences: list[float] = field(default_factory=list)
    
    @property
    def cost_usd(self) -> float:
        """Total estimated cost in USD."""
        return self.oracle_metrics.cost_usd
    
    @property
    def cost_str(self) -> str:
        """Formatted cost string."""
        cost = self.cost_usd
        if cost < 0.001:
            return f"${cost*1e6:.2f}µ"  # microUSD
        elif cost < 0.01:
            return f"${cost*1e3:.2f}m"  # milliUSD
        return f"${cost:.5f}"
    
    def summary_str(self) -> str:
        """Human-readable summary of all metrics."""
        lines = [
            f"Attacks:    {self.total_attacks} total ({self.hits} hit, {self.misses} miss, {self.errors} error)",
            f"Duration:   {self.duration_seconds:.2f}s",
            f"Throughput: {self.throughput:.2f} attacks/sec" if self.throughput > 0 else "Throughput: N/A",
            f"Oracle:     {self.oracle_metrics.total_calls} calls, {self.oracle_metrics.avg_latency_ms:.0f}ms avg, {self.cost_str} cost",
            f"Confidence: {self.avg_confidence:.2%} avg" if self.avg_confidence > 0 else "Confidence: N/A",
        ]
        if self.http_metrics.total_requests > 0:
            lines.append(
                f"HTTP:       {self.http_metrics.total_requests} requests, "
                f"{self.http_metrics.avg_latency_ms:.0f}ms avg, "
                f"{self.http_metrics.success_rate:.0%} success rate"
            )
        return "\n".join(lines)


@dataclass
class ScanMetricsCompare:
    """Metrics comparing sync vs async performance."""
    
    total_attacks: int
    sync_duration_seconds: float = 0.0
    async_duration_seconds: float = 0.0
    semaphore_limit: int = 15
    
    # Derived metrics
    errors_sync: int = 0
    errors_async: int = 0
    hits_sync: int = 0
    hits_async: int = 0
    
    # Memory usage (rough estimate)
    memory_peak_mb: float = 0.0
    
    @property
    def speedup(self) -> float:
        """How many times faster is async compared to sync?
        
        Typical speedup: 5-10x for remote endpoints, 1-2x for local.
        """
        if self.sync_duration_seconds <= 0:
            return 0.0
        return self.sync_duration_seconds / self.async_duration_seconds
    
    @property
    def sync_throughput(self) -> float:
        """Attacks per second in sync mode."""
        if self.sync_duration_seconds <= 0:
            return 0.0
        return self.total_attacks / self.sync_duration_seconds
    
    @property
    def async_throughput(self) -> float:
        """Attacks per second in async mode."""
        if self.async_duration_seconds <= 0:
            return 0.0
        return self.total_attacks / self.async_duration_seconds
    
    @property
    def time_saved_seconds(self) -> float:
        """How many seconds faster is async?"""
        return self.sync_duration_seconds - self.async_duration_seconds
    
    def summary_str(self) -> str:
        """Human-readable summary of metrics."""
        lines = [
            f"Sync:       {self.sync_duration_seconds:.2f}s ({self.sync_throughput:.2f} attacks/sec)",
            f"Async:      {self.async_duration_seconds:.2f}s ({self.async_throughput:.2f} attacks/sec)",
            f"Speedup:    {self.speedup:.1f}x faster",
            f"Saved:      {self.time_saved_seconds:.2f}s",
            f"Concurrent: {self.semaphore_limit} connections",
        ]
        return "\n".join(lines)
