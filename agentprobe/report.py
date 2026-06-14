"""Report — render a ScanReport to Rich-formatted terminal output and/or JSON.

Supports:
- Console rendering with Rich formatting (tables, panels, colors)
- JSON export with detailed statistics, metrics, and structured results
- Exit code determination based on findings
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentprobe.engine import ScanReport
from agentprobe.metrics import ScanMetrics


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def render_console(report: ScanReport, console: Console | None = None, metrics: Optional[ScanMetrics] = None) -> None:
    """Pretty-print a scan report to the terminal."""

    console = console or Console()

    # Summary panel
    summary = Text()
    summary.append(f"Target:   {report.target_name}\n", style="bold")
    summary.append(f"Attacks:  {report.total}\n")
    hits = len(report.hits)
    rate = report.success_rate * 100
    style = "red" if rate >= 30 else "yellow" if rate >= 10 else "green"
    summary.append(f"Hits:     {hits} ({rate:.0f}%)\n", style=style)
    
    # Add metrics if available
    if metrics:
        summary.append(f"Duration: {metrics.duration_seconds:.2f}s\n")
        summary.append(f"Cost:     {metrics.cost_str}\n", style="dim")
        if metrics.throughput > 0:
            summary.append(f"Speed:    {metrics.throughput:.1f} attacks/sec\n", style="dim")
    
    console.print(Panel(summary, title="AgentProbe scan", border_style="cyan"))

    if not report.hits:
        console.print("\n[green]No successful attacks. Target appears robust against this attack set.[/green]\n")
        return

    # By-category breakdown
    cat_table = Table(title="By category", show_header=True, header_style="bold magenta")
    cat_table.add_column("Category")
    cat_table.add_column("Hits / Total", justify="right")
    cat_table.add_column("Rate", justify="right")
    for cat, stats in sorted(report.by_category().items()):
        r = stats["hits"] / stats["total"] if stats["total"] else 0
        cat_table.add_row(
            cat,
            f"{stats['hits']} / {stats['total']}",
            f"{r * 100:.0f}%",
        )
    console.print(cat_table)
    console.print()

    # Findings table
    findings_table = Table(title="Findings", show_header=True, header_style="bold red")
    findings_table.add_column("Attack ID", style="cyan", no_wrap=False)
    findings_table.add_column("Confidence", justify="right")
    findings_table.add_column("Evidence")
    findings_table.add_column("Excerpt", overflow="fold")
    for r in report.hits:
        findings_table.add_row(
            r.attack_id,
            f"{r.confidence:.0%}",
            r.evidence,
            r.response_text[:100] + ("…" if len(r.response_text) > 100 else ""),
        )
    console.print(findings_table)


def write_json(
    report: ScanReport,
    path: Path,
    metrics: Optional[ScanMetrics] = None,
    scan_id: Optional[str] = None,
) -> None:
    """Persist the report as JSON for programmatic use / CI / paper analyses.
    
    JSON structure:
    {
      "scan_id": "uuid",
      "timestamp": "ISO8601",
      "target": "name",
      "statistics": {
        "total_attacks": 45,
        "hits": 15,
        "misses": 28,
        "errors": 2,
        "total_time_ms": 340,
        "cost_usd": 0.003,
        "avg_confidence": 0.87
      },
      "results": [...],
      "errors": [...]
    }
    """
    scan_id = scan_id or str(uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    
    # Separate hits, misses, and errors
    errors = [r for r in report.results if not r.success and r.confidence == 0.0]
    hits = [r for r in report.results if r.success]
    misses = [r for r in report.results if not r.success and r.confidence > 0.0]
    
    # Calculate average confidence (only from successful attacks)
    avg_confidence = 0.0
    if hits:
        avg_confidence = sum(r.confidence for r in hits) / len(hits)
    
    # Build statistics
    stats = {
        "total_attacks": report.total,
        "hits": len(hits),
        "misses": len(misses),
        "errors": len(errors),
        "avg_confidence": avg_confidence,
    }
    
    if metrics:
        stats["total_time_ms"] = int(metrics.duration_seconds * 1000)
        stats["cost_usd"] = round(metrics.cost_usd, 8)
        stats["throughput_attacks_per_sec"] = round(metrics.throughput, 2)
        if metrics.oracle_metrics.total_calls > 0:
            stats["oracle_calls"] = metrics.oracle_metrics.total_calls
            stats["oracle_avg_latency_ms"] = round(metrics.oracle_metrics.avg_latency_ms, 1)
            stats["oracle_total_tokens"] = metrics.oracle_metrics.total_tokens
        if metrics.http_metrics.total_requests > 0:
            stats["http_requests"] = metrics.http_metrics.total_requests
            stats["http_avg_latency_ms"] = round(metrics.http_metrics.avg_latency_ms, 1)
    
    # Build data structure
    data = {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "target": report.target_name,
        "statistics": stats,
        "by_category": report.by_category(),
        "results": [
            {
                "attack_id": r.attack_id,
                "success": r.success,
                "confidence": r.confidence,
                "evidence": r.evidence,
                "latency_ms": getattr(r, "latency_ms", None),
            }
            for r in report.results
        ],
    }
    
    # Add errors if any
    if errors:
        data["errors"] = [
            {
                "attack_id": r.attack_id,
                "evidence": r.evidence,
            }
            for r in errors
        ]
    
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
