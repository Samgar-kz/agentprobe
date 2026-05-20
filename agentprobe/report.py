"""Report — render a ScanReport to Rich-formatted terminal output and/or JSON."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentprobe.engine import ScanReport


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def render_console(report: ScanReport, console: Console | None = None) -> None:
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


def write_json(report: ScanReport, path: Path) -> None:
    """Persist the report as JSON for programmatic use / CI / paper analyses."""

    data = {
        "target": report.target_name,
        "total": report.total,
        "hits": len(report.hits),
        "success_rate": report.success_rate,
        "by_category": report.by_category(),
        "results": [asdict(r) for r in report.results],
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
