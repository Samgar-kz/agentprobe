"""CLI entry point. Run `agentprobe --help` after install to see commands."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner

from agentprobe import __version__
from agentprobe.adapters import DummyVulnerableAgent, HTTPAgent
from agentprobe.adapters.http_async import AsyncHTTPAgent
from agentprobe.attacks import all_attacks
from agentprobe.engine import run_scan
from agentprobe.engine_async import run_scan_async
from agentprobe.logging_config import configure_logging, get_logger
from agentprobe.report import render_console, write_json
from agentprobe.target import Target

logger = get_logger("cli")


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
    use_async: bool = False,
) -> Target:
    """Map CLI flags to a concrete Target instance.
    
    Args:
        target: Target type (dummy, http, http_async)
        endpoint: URL for HTTP targets
        input_field: JSON field for input
        output_field: JSON field for output
        auth_header: Optional Authorization header value
        use_async: If True, upgrade http → http_async
        
    Returns:
        Concrete Target instance
    """

    if target == "dummy":
        return DummyVulnerableAgent()
    
    if target == "http" or target == "http_async":
        if not endpoint:
            raise typer.BadParameter(f"--endpoint is required for target={target}")
        headers = {"Content-Type": "application/json"}
        if auth_header:
            headers["Authorization"] = auth_header
        
        # Auto-upgrade to async if flag is set
        if use_async or target == "http_async":
            return AsyncHTTPAgent(
                endpoint=endpoint,
                input_field=input_field,
                output_field=output_field,
                headers=headers,
            )
        else:
            return HTTPAgent(
                endpoint=endpoint,
                input_field=input_field,
                output_field=output_field,
                headers=headers,
            )
    
    raise typer.BadParameter(f"Unknown target: {target}. Use 'dummy', 'http', or 'http_async'.")


@app.command()
def scan(
    target: str = typer.Option("dummy", "--target", "-t", help="Target type: dummy | http | http_async"),
    endpoint: Optional[str] = typer.Option(None, "--endpoint", "-e", help="URL of the agent endpoint (for http/http_async)"),
    input_field: str = typer.Option("message", "--input-field", help="JSON field for input (http target)"),
    output_field: str = typer.Option("reply", "--output-field", help="JSON field for output (http target)"),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", help="Authorization header value"),
    categories: Optional[str] = typer.Option(
        None, "--categories", "-c", help="Comma-separated categories: pragmatic,register,discourse,codeswitch,classic"
    ),
    out_json: Optional[Path] = typer.Option(None, "--json-report", help="Write report as JSON to this path (--out-json also works)"),
    out_json_legacy: Optional[Path] = typer.Option(None, "--out-json", hidden=True, help="Deprecated: use --json-report"),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="Save logs to file (with rotation)"),
    verbose: int = typer.Option(0, "--verbose", "-v", help="Verbosity level: 0=quiet, 1=normal, 2=debug (stackable: -v for normal, -vv for debug)"),
    json_logs: bool = typer.Option(False, "--json-logs", help="Output logs as JSON"),
    fail_threshold: float = typer.Option(0.0, "--fail-threshold", help="Exit with non-zero if hit rate > threshold (0-1)"),
    oracle: str = typer.Option("semantic", "--oracle", help="Oracle type: semantic (LLM-based) | legacy (offline substring matching)"),
    oracle_model: Optional[str] = typer.Option(None, "--oracle-model", help="Override oracle LLM model (e.g., gpt-4o-mini)"),
    min_confidence: float = typer.Option(0.7, "--min-confidence", help="Minimum confidence threshold for oracle judgment (0.0-1.0)"),
    oracle_timeout: int = typer.Option(30, "--oracle-timeout", help="LLM oracle timeout in seconds"),
    use_async: bool = typer.Option(False, "--async", help="Use async mode for HTTPAgent (faster for remote targets)"),
    concurrency: int = typer.Option(15, "--concurrency", help="Max concurrent connections in async mode (default: 15)"),
) -> None:
    """Run a security scan against an LLM agent.
    
    Exit codes:
      0: Success (no vulnerabilities or below fail_threshold)
      1: General error
      2: Found vulnerabilities (if --fail-threshold exceeded)
      3: Configuration error
    """

    # Handle legacy --out-json flag
    final_out_json = out_json or out_json_legacy
    
    # Configure logging based on verbosity level
    log_level_map = {0: "WARNING", 1: "INFO", 2: "DEBUG"}
    log_level = log_level_map.get(min(verbose, 2), "INFO")
    configure_logging(level=log_level, json_output=json_logs, log_file=str(log_file) if log_file else None)
    logger.info("AgentProbe scan started", extra={"target": target, "oracle": oracle, "verbosity": verbose})

    # Validate oracle configuration
    if oracle not in ("semantic", "legacy"):
        logger.error(f"Invalid oracle type: {oracle}")
        console.print(f"[red]Error: --oracle must be 'semantic' or 'legacy', got '{oracle}'[/red]")
        raise typer.Exit(code=3)

    if oracle == "semantic" and oracle_model:
        # Set environment variable for model override
        os.environ["LLM_MODEL"] = oracle_model
        logger.info(f"Oracle model override: {oracle_model}")

    if oracle == "semantic":
        if not os.environ.get("OPENAI_API_KEY"):
            logger.warning("OPENAI_API_KEY not set; semantic oracle may fail")
            console.print("[yellow]Warning: OPENAI_API_KEY not set. Semantic oracle requires it.[/yellow]")

    if not (0.0 <= min_confidence <= 1.0):
        logger.error(f"Invalid min_confidence: {min_confidence}")
        console.print(f"[red]Error: --min-confidence must be between 0.0 and 1.0[/red]")
        raise typer.Exit(code=3)

    try:
        tgt = _resolve_target(target, endpoint, input_field, output_field, auth_header, use_async)
    except typer.BadParameter as e:
        logger.error(f"Configuration error: {e}", extra={"retry_attempt": 0})
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=3)

    cats = set(categories.split(",")) if categories else None
    if cats:
        logger.info(f"Category filter: {cats}")

    attacks = all_attacks()
    total = len(attacks) if not cats else sum(1 for a in attacks if a.category in cats)
    
    mode_str = "async" if (use_async or target == "http_async") else "sync"
    console.print(
        f"[dim]Loaded {total} attacks. Starting {mode_str} scan against "
        f"[cyan]{tgt.name}[/cyan] (concurrency: {concurrency})…[/dim]\n"
    )
    logger.info(f"Loaded {total} attacks (mode={mode_str}, concurrency={concurrency})")

    spinner = Spinner("dots", text="Scanning…")
    metrics = None
    try:
        with Live(spinner, console=console, refresh_per_second=10) as live:
            def progress(idx: int, n: int, attack):
                live.update(Spinner("dots", text=f"[{idx}/{n}] {attack.id}"))
                if verbose >= 2:
                    logger.debug(f"Running attack {attack.id}")

            # Use async engine if requested
            if use_async or target == "http_async":
                import asyncio
                report = asyncio.run(
                    run_scan_async(
                        tgt,
                        categories=cats,
                        semaphore_limit=concurrency,
                        progress_callback=progress,
                        oracle_type=oracle,
                        min_confidence=min_confidence,
                    )
                )
                logger.info(
                    f"Async scan completed: {report.throughput:.2f} attacks/sec, "
                    f"duration: {report.duration_seconds:.2f}s"
                )
            else:
                # Use traditional sync engine with metrics tracking
                report, metrics = run_scan(
                    tgt,
                    categories=cats,
                    progress_callback=progress,
                    oracle_type=oracle,
                    min_confidence=min_confidence,
                    track_metrics=True,
                )
    except Exception as e:
        logger.error(f"Scan failed: {e}", extra={"retry_attempt": 0})
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(code=1)

    console.print()
    render_console(report, console, metrics=metrics)
    
    # Show detailed metrics if available
    if metrics:
        console.print(f"\n[dim]{metrics.summary_str()}[/dim]")
    
    # Show async metrics if available
    if hasattr(report, 'duration_seconds') and report.duration_seconds > 0:
        console.print(
            f"\n[dim]Performance: {report.throughput:.2f} attacks/sec, "
            f"duration {report.duration_seconds:.2f}s, "
            f"{report.concurrent_connections} concurrent[/dim]"
        )
        if report.errors:
            console.print(f"[yellow]Warnings: {len(report.errors)} non-fatal errors[/yellow]")
            if verbose >= 2:
                for err in report.errors[:5]:  # Show first 5 errors
                    console.print(f"  [dim]{err}[/dim]")
    
    logger.info(
        f"Scan completed: {len(report.hits)} hits / {report.total} attacks",
        extra={"hits": len(report.hits), "total": report.total, "rate": report.success_rate},
    )

    if final_out_json:
        write_json(report, final_out_json, metrics=metrics)
        console.print(f"\n[dim]Report written to {final_out_json}[/dim]")
        logger.info(f"JSON report written to {final_out_json}")

    # Determine exit code based on threshold
    if report.success_rate > fail_threshold:
        logger.warning(f"Hit rate {report.success_rate:.1%} exceeds threshold {fail_threshold:.1%}")
        raise typer.Exit(code=2)
    raise typer.Exit(code=0)


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


@app.command()
def health(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed health info"),
) -> None:
    """Check system health and readiness."""
    from agentprobe.llm_oracle import SemanticOracle

    console.print("[bold]AgentProbe Health Check[/bold]\n")

    # Check dependencies
    checks = {
        "httpx": False,
        "pydantic": False,
        "typer": False,
        "rich": False,
        "Claude API": False,
    }

    try:
        import httpx
        checks["httpx"] = True
    except ImportError:
        pass

    try:
        import pydantic
        checks["pydantic"] = True
    except ImportError:
        pass

    try:
        import typer
        checks["typer"] = True
    except ImportError:
        pass

    try:
        import rich
        checks["rich"] = True
    except ImportError:
        pass

    oracle = SemanticOracle()
    checks["Claude API"] = oracle.is_available()

    for name, available in checks.items():
        status = "[green]✓[/green]" if available else "[red]✗[/red]"
        console.print(f"  {status} {name}")

    all_ok = all(checks.values())
    console.print()
    if all_ok:
        console.print("[green]All systems operational[/green]")
        raise typer.Exit(code=0)
    else:
        missing = [k for k, v in checks.items() if not v]
        console.print(f"[yellow]Missing: {', '.join(missing)}[/yellow]")
        if "Claude API" in missing:
            console.print("[dim]Tip: Set ANTHROPIC_API_KEY to enable LLM-based semantic judgment[/dim]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
