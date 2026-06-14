"""Performance metrics and cost tracking for AgentProbe scans.

Tracks:
- Total attacks run, hits/misses/errors
- HTTP request/response times
- Oracle call tokens and latencies
- Cost estimation based on token usage
- Throughput (attacks/sec) for async mode
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from agentprobe.logging_config import get_logger

logger = get_logger("metrics")

# Fallback price (USD per 1M tokens) used when a model is absent from
# MODEL_PRICING. Matches gpt-4o-mini, the default oracle model.
_DEFAULT_PRICE_PER_1M = 0.15


def wilson_ci(successes: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    """Wilson score 95% CI for a binomial proportion — robust for small n.
    
    Returns: (point_estimate, lower_bound, upper_bound)
    """
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (p, max(0.0, center - margin), min(1.0, center + margin))


def two_proportion_pvalue(x1: int, n1: int, x2: int, n2: int) -> float:
    """Two-sided p-value for the difference between two independent proportions.

    Pooled two-proportion z-test, used by `agentprobe compare` to decide whether a
    change between two scans is a real regression/improvement or just noise.
    Dependency-free (normal CDF via math.erf — no scipy).

    Returns 1.0 when the test is undefined (empty sample or zero variance).
    """
    if n1 == 0 or n2 == 0:
        return 1.0
    p1 = x1 / n1
    p2 = x2 / n2
    p_pool = (x1 + x2) / (n1 + n2)
    var = p_pool * (1 - p_pool) * (1 / n1 + 1 / n2)
    if var <= 0:
        return 1.0
    z = (p1 - p2) / math.sqrt(var)
    return 2.0 * (1.0 - 0.5 * (1.0 + math.erf(abs(z) / math.sqrt(2.0))))


# Model pricing (USD per 1M input tokens). Approximate; used only for the
# cost estimate in scan metrics. Keys are matched against the model id reported
# by the oracle/agent; unknown models fall back to _DEFAULT_PRICE_PER_1M.
MODEL_PRICING = {
    "gpt-4o-mini": 0.15,
    "gpt-4o": 5.0,
    "claude-haiku-4-5": 1.00,
    "gemini-2.5-flash": 0.30,
    "gemini-2.0-flash": 0.10,
    "gemini-1.5-flash": 0.075,
    "llama-3.3-70b-versatile": 0.59,   # Groq
    "deepseek-chat": 0.27,
    "mistral-small-latest": 0.20,
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
        price_per_1m = MODEL_PRICING.get(self.model)
        if price_per_1m is None:
            logger.warning(
                "No pricing for model %r; estimating at the default $%.2f/1M tokens. "
                "Add it to MODEL_PRICING for an accurate cost.",
                self.model,
                _DEFAULT_PRICE_PER_1M,
            )
            price_per_1m = _DEFAULT_PRICE_PER_1M
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
