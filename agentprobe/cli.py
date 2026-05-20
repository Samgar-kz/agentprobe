"""CLI entry point. Run `agentprobe --help` after install to see commands."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner

from agentprobe import __version__
from agentprobe.adapters import DummyVulnerableAgent, HTTPAgent
from agentprobe.attacks import all_attacks
from agentprobe.engine import run_scan
from agentprobe.report import render_console, write_json
from agentprobe.target import Target


app = typer.Typer(
    help="AgentProbe — security scanner for LLM agents.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


def _resolve_target(
    target: str,
    endpoint: Optional[str],
    input_field: str,
    output_field: str,
    auth_header: Optional[str],
) -> Target:
    """Map CLI flags to a concrete Target instance."""

    if target == "dummy":
        return DummyVulnerableAgent()
    if target == "http":
        if not endpoint:
            raise typer.BadParameter("--endpoint is required for target=http")
        headers = {"Content-Type": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header
        return HTTPAgent(
            endpoint=endpoint,
            input_field=input_field,
            output_field=output_field,
            headers=headers,
        )
    raise typer.BadParameter(f"Unknown target: {target}. Use 'dummy' or 'http'.")


@app.command()
def scan(
    target: str = typer.Option("dummy", "--target", "-t", help="Target type: dummy | http"),
    endpoint: Optional[str] = typer.Option(None, "--endpoint", "-e", help="URL of the agent endpoint (for http)"),
    input_field: str = typer.Option("message", "--input-field", help="JSON field for input (http target)"),
    output_field: str = typer.Option("reply", "--output-field", help="JSON field for output (http target)"),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", help="Authorization header value"),
    categories: Optional[str] = typer.Option(
        None, "--categories", "-c", help="Comma-separated categories: pragmatic,register,discourse,codeswitch,classic"
    ),
    out_json: Optional[Path] = typer.Option(None, "--out-json", help="Write report as JSON to this path"),
) -> None:
    """Run a security scan against an LLM agent."""

    tgt = _resolve_target(target, endpoint, input_field, output_field, auth_header)
    cats = set(categories.split(",")) if categories else None

    attacks = all_attacks()
    total = len(attacks) if not cats else sum(1 for a in attacks if a.category in cats)
    console.print(f"[dim]Loaded {total} attacks. Starting scan against [cyan]{tgt.name}[/cyan]…[/dim]\n")

    spinner = Spinner("dots", text="Scanning…")
    with Live(spinner, console=console, refresh_per_second=10) as live:
        def progress(idx: int, n: int, attack):
            live.update(Spinner("dots", text=f"[{idx}/{n}] {attack.id}"))

        report = run_scan(tgt, categories=cats, progress_callback=progress)

    console.print()
    render_console(report, console)

    if out_json:
        write_json(report, out_json)
        console.print(f"\n[dim]Report written to {out_json}[/dim]")


@app.command()
def list_attacks(
    category: Optional[str] = typer.Option(None, "--category", "-c"),
) -> None:
    """List all attacks in the catalogue."""

    attacks = all_attacks()
    if category:
        attacks = [a for a in attacks if a.category == category]

    console.print(f"[bold]{len(attacks)} attacks[/bold]\n")
    for a in attacks:
        console.print(f"  [cyan]{a.id}[/cyan]  [{a.severity.value}]")
        console.print(f"    [dim]{a.description}[/dim]")


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"agentprobe {__version__}")


if __name__ == "__main__":
    app()
