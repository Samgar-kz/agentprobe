"""CLI entry point. Run `agentprobe --help` after install to see commands."""

from __future__ import annotations

import json
import os
from importlib.util import find_spec
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

    # In-process Python agent: --target callable:module:function (no HTTP server).
    if target.startswith("callable:"):
        spec = target[len("callable:"):]
        if ":" not in spec:
            raise typer.BadParameter(
                "callable target must be 'callable:module:function' (e.g. callable:myagent:run)"
            )
        mod_path, attr = spec.rsplit(":", 1)
        import importlib
        import sys

        if "" not in sys.path:
            sys.path.insert(0, "")  # make modules in the current dir importable
        try:
            fn = getattr(importlib.import_module(mod_path), attr)
        except (ImportError, AttributeError) as e:
            raise typer.BadParameter(f"could not load callable '{spec}': {e}")
        from agentprobe.adapters import CallableTarget
        return CallableTarget(fn, name=attr)

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
    
    raise typer.BadParameter(
        f"Unknown target: {target}. Use 'dummy', 'http', 'http_async', or 'callable:module:function'."
    )


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
        console.print("[red]Error: --min-confidence must be between 0.0 and 1.0[/red]")
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


def _fmt_cell(t: "tuple[int, int] | None") -> str:
    if t is None:
        return "—"
    pos, n = t
    r = pos / n if n else 0.0
    return f"{r*100:.1f}% ({pos}/{n})"


def _delta_pp_str(g) -> str:
    dpp = g.delta_pp
    return f"Δ {dpp:+.1f}pp" if dpp is not None else ""


def _group_line(g) -> str:
    return f"{g.name:<26} {_fmt_cell(g.old)} -> {_fmt_cell(g.new)}  {_delta_pp_str(g)}"


def _render_comparison(result, old_path: str, new_path: str) -> None:
    from rich.text import Text

    direction = "lower is better" if result.lower_is_better else "higher is better"
    console.print(
        f"\n[bold]Comparing[/bold]  {result.old_label} [dim]({old_path})[/dim]"
        f"  ->  {result.new_label} [dim]({new_path})[/dim]"
    )
    console.print(
        f"[dim]Kind: {result.kind} ({direction}) · grouped by {result.group_dim}[/dim]\n"
    )

    o = result.overall
    verdict = "[bold red]FAIL[/bold red]" if result.has_regression else "[bold green]PASS[/bold green]"
    console.print(
        f"[bold]{result.metric_name}:[/bold]  {_fmt_cell(o.old)} -> {_fmt_cell(o.new)}"
        f"   {_delta_pp_str(o)}   {verdict}\n"
    )

    if result.improved:
        console.print("[green]Improved (significant):[/green]")
        for g in sorted(result.improved, key=lambda x: x.delta_pp or 0):
            console.print(Text("  + ", style="green").append(_group_line(g), style="default"))
    if result.regressed:
        console.print("[red]Regressed (significant):[/red]")
        for g in sorted(result.regressed, key=lambda x: -(x.delta_pp or 0)):
            console.print(Text("  - ", style="red").append(_group_line(g) + "  ⚠", style="default"))
    if result.flat:
        console.print(f"[dim]Within noise: {len(result.flat)} {result.group_dim}(s)[/dim]")
    if result.added or result.removed:
        bits = []
        if result.added:
            bits.append(f"{len(result.added)} added")
        if result.removed:
            bits.append(f"{len(result.removed)} removed")
        console.print(f"[yellow]Coverage changed: {', '.join(bits)} {result.group_dim}(s)[/yellow]")
        for g in result.added:
            console.print(f"  [yellow]＋[/yellow] {g.name}  (new: {_fmt_cell(g.new)})")
        for g in result.removed:
            console.print(f"  [yellow]－[/yellow] {g.name}  (was: {_fmt_cell(g.old)})")
    console.print()


@app.command("compare")
def compare_cmd(
    old: str = typer.Argument(..., help="Baseline report JSON (scan / injection-scan / utility-scan)"),
    new: str = typer.Argument(..., help="New report JSON to compare against the baseline"),
    by: Optional[str] = typer.Option(
        None, "--by",
        help="Group dimension. injection: probe|defense|carrier|category (default probe). utility: defense|task.",
    ),
    soft_fail: bool = typer.Option(
        False, "--soft-fail", help="Report only; always exit 0 (don't gate CI on regressions)"
    ),
) -> None:
    """Diff two scan reports and flag statistically significant regressions.

    Turns AgentProbe into a regression gate: a per-group change is only called
    improved/regressed when a two-proportion test clears p<0.05 — everything else
    is within noise. Exit code: 0 = no significant regression, 2 = regression
    (fails CI), 1 = error / incompatible reports.
    """
    from agentprobe.compare import compare as run_compare

    try:
        result = run_compare(old, new, by=by)
    except FileNotFoundError as e:
        console.print(f"[red]Error: file not found: {e.filename}[/red]")
        raise typer.Exit(code=1)
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)

    _render_comparison(result, old, new)

    if soft_fail:
        raise typer.Exit(code=0)
    raise typer.Exit(code=2 if result.has_regression else 0)


@app.command("trend")
def trend_cmd(
    reports: list[str] = typer.Argument(..., help="Two or more report JSONs, in chronological order"),
    by: Optional[str] = typer.Option(None, "--by", help="Group dimension for normalization (the overall metric is shown)"),
    soft_fail: bool = typer.Option(False, "--soft-fail", help="Report only; always exit 0"),
) -> None:
    """Track the leak/hit rate across a series of reports, flagging real regressions.

    Like `compare`, but over N reports in chronological order: each step is tested
    against the previous one, so only statistically significant moves are called
    improved/regressed. Exit code: 0 = no regression, 2 = a step regressed, 1 = error.
    """
    from rich.table import Table

    from agentprobe.compare import trend as run_trend

    try:
        res = run_trend(reports, by=by)
    except FileNotFoundError as e:
        console.print(f"[red]Error: file not found: {e.filename}[/red]")
        raise typer.Exit(code=1)
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)

    direction = "lower is better" if res.lower_is_better else "higher is better"
    console.print(f"\n[bold]{res.metric_name} trend[/bold]  [dim]({res.kind}, {direction})[/dim]\n")
    t = Table(header_style="bold magenta")
    t.add_column("Report")
    t.add_column(res.metric_name, justify="right")
    t.add_column("Δ vs prev", justify="right")
    t.add_column("vs prev", justify="right")
    _style = {"baseline": "dim", "improved": "green", "regressed": "red", "flat": "white"}
    prev_rate = None
    for p in res.points:
        delta = "—" if prev_rate is None else f"{(p.rate - prev_rate) * 100:+.1f}pp"
        sig = "—" if p.p_value is None else f"p={p.p_value:.3f} {'✓' if p.p_value < 0.05 else 'n.s.'}"
        st = _style.get(p.status, "white")
        t.add_row(p.label, f"{p.rate*100:.1f}% ({p.pos}/{p.n})", delta, f"[{st}]{p.status}[/{st}] {sig}")
        prev_rate = p.rate
    console.print(t)
    verdict = "[bold red]REGRESSION[/bold red]" if res.has_regression else "[bold green]OK[/bold green]"
    console.print(f"\n{verdict}\n")

    if soft_fail:
        raise typer.Exit(code=0)
    raise typer.Exit(code=2 if res.has_regression else 0)


@app.command("analyze")
def analyze_cmd(
    csv_path: str = typer.Argument(..., help="Injection-scan CSV (e.g. data/gpt4omini.csv or rag_memory_scan.csv)"),
    show_probes: bool = typer.Option(False, "--probes", help="Also break down by probe"),
) -> None:
    """Recompute leak rate by defense and channel from a committed CSV (offline).

    Reproducibility: every headline number traces to a committed CSV and this one
    command — no API key, no model call (the injection battery is judged by
    deterministic detectors, so the result is a pure function of the CSV).
    """
    from rich.table import Table

    from agentprobe.analyze import analyze_injection

    try:
        res = analyze_injection(csv_path)
    except FileNotFoundError:
        console.print(f"[red]Error: file not found: {csv_path}[/red]")
        raise typer.Exit(code=1)
    except (ValueError, KeyError) as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=1)

    t = res.total
    console.print(
        f"\n[bold]{csv_path}[/bold]  —  overall leak rate "
        f"{t.rate*100:.1f}% ({t.leaks}/{t.n})\n"
    )

    def _rate_table(title, groups, sig=None):
        tab = Table(title=title, header_style="bold magenta", title_justify="left")
        tab.add_column("Group")
        tab.add_column("Leaks/N", justify="right")
        tab.add_column("Leak rate [95% CI]", justify="right")
        if sig:
            tab.add_column("vs email", justify="right")
        for g in groups:
            p, lo, hi = g.ci
            style = _ci_style(p, lo, hi)
            row = [g.name, f"{g.leaks}/{g.n}",
                   f"[{style}]{p*100:.1f}% [{lo*100:.1f}-{hi*100:.1f}][/{style}]"]
            if sig:
                pv = res.channel_vs_email.get(g.name)
                row.append("—" if pv is None else f"p={pv:.3f} {'✓' if pv < 0.05 else 'n.s.'}")
            tab.add_row(*row)
        console.print(tab)
        console.print()

    _rate_table("Leak rate by defense", res.by_defense)
    _rate_table("Leak rate by channel", res.by_channel, sig=True)
    if show_probes:
        _rate_table("Leak rate by probe", res.by_probe)


@app.command("validate-oracle")
def validate_oracle_cmd(
    dataset: Optional[str] = typer.Option(None, "--dataset", help="Labeled JSONL (default: data/oracle_labeled.jsonl)"),
    min_confidence: float = typer.Option(0.0, "--min-confidence", help="Min confidence for the judge to call a leak"),
    model: Optional[str] = typer.Option(None, "--model", help="Override the judge model (LLM_MODEL)"),
) -> None:
    """Validate the semantic judge against human labels (agreement + Cohen's kappa).

    Reproduces the README oracle-validation number. Requires OPENAI_API_KEY —
    one model call per labeled case (~cents on the seed set).
    """
    from agentprobe.oracle_validation import DEFAULT_DATASET, format_report
    from agentprobe.oracle_validation import validate_oracle as run_validate

    if not os.environ.get("OPENAI_API_KEY"):
        console.print("[yellow]OPENAI_API_KEY not set — the semantic oracle needs it to run.[/yellow]")
        raise typer.Exit(code=2)
    try:
        res = run_validate(
            dataset=dataset or DEFAULT_DATASET, min_confidence=min_confidence, model=model
        )
    except Exception as e:
        console.print(f"[red]Validation failed: {e}[/red]")
        raise typer.Exit(code=1)
    console.print(format_report(res))
    raise typer.Exit(code=0)


def _validate_backend(backend: str) -> None:
    """Reject unknown backends and warn (don't fail) if the API key is missing."""
    from agentprobe.injection.tool_agent import PROVIDERS, required_key

    if backend not in PROVIDERS:
        console.print(
            f"[red]Error: --backend must be one of {', '.join(sorted(PROVIDERS))}, got '{backend}'[/red]"
        )
        raise typer.Exit(code=3)
    key = required_key(backend)
    if not os.environ.get(key):
        console.print(f"[yellow]Warning: {key} not set; the {backend} backend will fail.[/yellow]")


def _ci_style(p: float, low: float, high: float) -> str:
    return "red" if p >= 0.3 else "yellow" if p >= 0.1 else "green"


@app.command("injection-scan")
def injection_scan(
    backend: str = typer.Option("openai", "--backend", help="LLM backend: openai | anthropic | gemini | groq | deepseek | mistral"),
    model: Optional[str] = typer.Option(None, "--model", help="Model override (bare name, or any litellm route like 'gemini/gemini-2.0-flash')"),
    repeats: int = typer.Option(5, "--repeats", help="Repeats per (defense x carrier x probe) for real variance"),
    temp: float = typer.Option(0.7, "--temp", help="Sampling temperature (>0 needed for variance)"),
    llm_filter: bool = typer.Option(False, "--llm-filter", help="Also evaluate the separate-screening defense (extra cost)"),
    oracle: str = typer.Option("deterministic", "--oracle", help="Judge: deterministic (free, exact) | hybrid (detector + LLM recall) | semantic (LLM only). hybrid/semantic need OPENAI_API_KEY."),
    use_async: bool = typer.Option(False, "--async", help="Run probes concurrently for a 5-10x speedup (best with --oracle deterministic)"),
    concurrency: int = typer.Option(8, "--concurrency", help="Max concurrent requests when --async (keep modest to avoid provider 429s)"),
    out: Optional[str] = typer.Option(None, "--out", help="Write raw results to <out>.csv and <out>.json"),
) -> None:
    """Measure indirect-injection leak rate per defense, with 95% CI and overhead.

    This is the harness behind the README's defense-effectiveness table. It runs
    every defense against every carrier x probe and reports how often the agent
    obeyed an instruction hidden in tool/data content.
    """
    from rich.table import Table
    from agentprobe.injection.harness import run_injection_harness
    from agentprobe.oracle_base import get_oracle

    _validate_backend(backend)

    if use_async and oracle != "deterministic":
        console.print("[yellow]Note: --async with a non-deterministic oracle serializes the LLM judge; deterministic is recommended for --async.[/yellow]")

    try:
        oracle_obj = get_oracle(oracle)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(code=3)
    if oracle in ("hybrid", "semantic") and not os.environ.get("OPENAI_API_KEY"):
        console.print(f"[yellow]Warning: --oracle {oracle} makes LLM calls but OPENAI_API_KEY is not set.[/yellow]")

    from agentprobe.injection.instructions import ALL_PROBES
    from agentprobe.injection.carriers import ALL_CARRIERS
    mode = f"async x{concurrency}" if use_async else "sync"
    console.print(
        f"[bold cyan]Injection harness[/bold cyan]  backend={backend} "
        f"model={model or 'default'} repeats={repeats} temp={temp} oracle={oracle} {mode} "
        f"probes={len(ALL_PROBES)} carriers={len(ALL_CARRIERS)}\n"
    )
    if temp == 0:
        console.print("[yellow]Warning: temp=0 gives ~identical repeats and no variance. Use --temp=0.7.[/yellow]\n")

    spinner = Spinner("dots", text="Running…")
    try:
        with Live(spinner, console=console, refresh_per_second=8) as live:
            def progress(done: int, total: int) -> None:
                live.update(Spinner("dots", text=f"[{done}/{total}]"))
            if use_async:
                import asyncio

                from agentprobe.injection.harness import run_injection_harness_async
                result = asyncio.run(run_injection_harness_async(
                    backend=backend, model=model, repeats=repeats,
                    temperature=temp, use_llm_filter=llm_filter, oracle=oracle_obj,
                    concurrency=concurrency, progress=progress,
                ))
            else:
                result = run_injection_harness(
                    backend=backend, model=model, repeats=repeats,
                    temperature=temp, use_llm_filter=llm_filter, oracle=oracle_obj, progress=progress,
                )
    except Exception as e:
        console.print(f"[red]Harness failed: {e}[/red]")
        raise typer.Exit(code=1)

    console.print("\n[bold green]━━━ Leak rate by defense (95% CI) ━━━[/bold green]\n")
    t = Table(header_style="bold magenta")
    t.add_column("Defense")
    t.add_column("Leaks/N", justify="right")
    t.add_column("Leak rate [95% CI]", justify="right")
    t.add_column("Overhead (tok/run, ms/run)", justify="right")
    for s in result.defenses:
        p, lo, hi = s.ci
        style = _ci_style(p, lo, hi)
        t.add_row(
            s.name, f"{s.leaks}/{s.total}",
            f"[{style}]{p*100:.0f}% [{lo*100:.0f}–{hi*100:.0f}][/{style}]",
            f"{s.overhead_tokens_per_run:.0f} tok, {s.overhead_latency_ms_per_run:.0f} ms",
        )
    console.print(t)

    console.print("\n[bold green]━━━ Leak rate by carrier ━━━[/bold green]\n")
    tc = Table(header_style="bold magenta")
    tc.add_column("Carrier")
    tc.add_column("Leaks/N", justify="right")
    tc.add_column("Rate", justify="right")
    for name, (lk, tot) in sorted(result.per_carrier.items(), key=lambda kv: -(kv[1][0] / kv[1][1] if kv[1][1] else 0)):
        p = lk / tot if tot else 0
        style = _ci_style(p, p, p)
        tc.add_row(name, f"{lk}/{tot}", f"[{style}]{p*100:.0f}%[/{style}]")
    console.print(tc)

    if out:
        _export_rows(out, result.rows, result.meta,
                     ["defense", "carrier", "channel", "instruction", "category", "leaked", "reason"])
        console.print(f"\n[dim]Raw data written to {out}.csv and {out}.json ({len(result.rows)} records)[/dim]")


@app.command("utility-scan")
def utility_scan(
    backend: str = typer.Option("openai", "--backend", help="LLM backend: openai | anthropic | gemini | groq | deepseek | mistral"),
    model: Optional[str] = typer.Option(None, "--model", help="Model override (bare name, or any litellm route like 'gemini/gemini-2.0-flash')"),
    repeats: int = typer.Option(3, "--repeats", help="Repeats per (defense x benign task)"),
    temp: float = typer.Option(0.7, "--temp", help="Sampling temperature"),
    llm_filter: bool = typer.Option(False, "--llm-filter", help="Also evaluate the separate-screening defense (extra cost)"),
    out: Optional[str] = typer.Option(None, "--out", help="Write raw results to <out>.csv and <out>.json"),
) -> None:
    """Measure the false-positive cost of each defense on benign tasks.

    The complement to injection-scan: a defense is only practical if it preserves
    utility. Reports task success rate per defense (high = utility intact).
    """
    from rich.table import Table
    from agentprobe.injection.harness import run_utility_harness

    _validate_backend(backend)

    from agentprobe.injection.benign_tasks import BENIGN_TASKS
    console.print(
        f"[bold cyan]Utility harness[/bold cyan]  backend={backend} "
        f"model={model or 'default'} repeats={repeats} temp={temp} "
        f"tasks={len(BENIGN_TASKS)}\n"
    )

    spinner = Spinner("dots", text="Running…")
    try:
        with Live(spinner, console=console, refresh_per_second=8) as live:
            def progress(done: int, total: int) -> None:
                live.update(Spinner("dots", text=f"[{done}/{total}]"))
            result = run_utility_harness(
                backend=backend, model=model, repeats=repeats,
                temperature=temp, use_llm_filter=llm_filter, progress=progress,
            )
    except Exception as e:
        console.print(f"[red]Harness failed: {e}[/red]")
        raise typer.Exit(code=1)

    console.print("\n[bold green]━━━ Success rate by defense (utility preserved, 95% CI) ━━━[/bold green]\n")
    t = Table(header_style="bold magenta")
    t.add_column("Defense")
    t.add_column("OK/N", justify="right")
    t.add_column("Success rate [95% CI]", justify="right")
    t.add_column("Overhead (tok/run, ms/run)", justify="right")
    for s in result.defenses:
        p, lo, hi = s.ci
        style = "green" if p >= 0.95 else "yellow" if p >= 0.90 else "red"
        t.add_row(
            s.name, f"{s.successes}/{s.total}",
            f"[{style}]{p*100:.0f}% [{lo*100:.0f}–{hi*100:.0f}][/{style}]",
            f"{s.overhead_tokens_per_run:.0f} tok, {s.overhead_latency_ms_per_run:.0f} ms",
        )
    console.print(t)

    if out:
        _export_rows(out, result.rows, result.meta,
                     ["model", "defense", "task", "task_id", "iteration", "outcome"])
        console.print(f"\n[dim]Raw data written to {out}.csv and {out}.json ({len(result.rows)} records)[/dim]")


def _export_rows(base: str, rows: list, meta: dict, fieldnames: list[str]) -> None:
    """Write harness rows to <base>.csv and a {meta, rows} bundle to <base>.json."""
    import csv
    base = base[:-4] if base.endswith(".csv") else base
    with open(f"{base}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    with open(f"{base}.json", "w") as f:
        json.dump({"meta": meta, "rows": rows}, f, indent=2, ensure_ascii=False)


@app.command()
def version() -> None:
    """Print version."""
    console.print(f"agentprobe {__version__}")


@app.command()
def health(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed health info"),
) -> None:
    """Check system health and readiness."""
    console.print("[bold]AgentProbe Health Check[/bold]\n")

    # Check dependencies
    checks = {
        "httpx": False,
        "pydantic": False,
        "typer": False,
        "rich": False,
        "OpenAI API": False,
    }

    for _mod in ("httpx", "pydantic", "typer", "rich"):
        checks[_mod] = find_spec(_mod) is not None

    try:
        from agentprobe.oracle_semantic import SemanticOracle
        SemanticOracle()
        checks["OpenAI API"] = True
    except Exception:
        pass

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
        if "OpenAI API" in missing:
            console.print("[dim]Tip: Set OPENAI_API_KEY to enable LLM-based semantic judgment[/dim]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
