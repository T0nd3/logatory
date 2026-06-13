"""CLI command group: logatory docker — analyze logs from local containers."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.docker import DockerAdapter
from logatory.cli._pipeline import print_tail_header, print_tail_summary, run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg, parse_lookback_utc

app = typer.Typer(help="Analyze logs from local Docker containers — no log stack needed.")


@app.command("scan")
def docker_scan(
    name: Annotated[
        Optional[str], typer.Option("--name", "-n", help="Filter containers by name (substring).")
    ] = None,
    label: Annotated[
        Optional[str], typer.Option("--label", "-l", help="Filter by label: 'key' or 'key=value'.")
    ] = None,
    include_stopped: Annotated[
        bool, typer.Option("--all", "-a", help="Include stopped containers.")
    ] = False,
    tail: Annotated[int, typer.Option("--tail", help="Log lines to fetch per container.")] = 200,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    limit: Annotated[int, typer.Option("--limit", help="Max events to display.")] = 50,
    show_all: Annotated[bool, typer.Option("--show-all", help="Display every event.")] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
) -> None:
    """Fetch logs from local Docker containers, redact PII, run detection rules.

    No log-aggregation stack required — the logs come straight from the
    Docker daemon. Each event is tagged with its container name.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = DockerAdapter(name=name, label=label, include_stopped=include_stopped, tail=tail)
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except ImportError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error talking to Docker: {e}", err=True)
        raise typer.Exit(1)

    containers = sorted({e.source for e in result.events})
    render_scan(
        result,
        source_label=f"Docker ({len(containers)} container(s))",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=[f"  Containers : {', '.join(containers)}"] if containers else None,
    )


@app.command("tail")
def docker_tail(
    name: Annotated[
        Optional[str], typer.Option("--name", "-n", help="Filter containers by name (substring).")
    ] = None,
    label: Annotated[
        Optional[str], typer.Option("--label", "-l", help="Filter by label: 'key' or 'key=value'.")
    ] = None,
    include_stopped: Annotated[
        bool, typer.Option("--all", "-a", help="Include stopped containers.")
    ] = False,
    since: Annotated[
        str, typer.Option("--since", help="Initial lookback window: 30s, 5m, 1h.")
    ] = "1m",
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between polls.")
    ] = 3.0,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
    track_findings: Annotated[
        bool, typer.Option("--track-findings", help="Persist HIGH/CRITICAL findings to SQLite.")
    ] = False,
    alert_webhook: Annotated[
        Optional[str], typer.Option("--alert-webhook", help="POST findings as JSON to this URL.")
    ] = None,
    alert_min_severity: Annotated[
        str, typer.Option("--alert-min-severity", help="Minimum severity to fire the webhook.")
    ] = "high",
) -> None:
    """Follow local Docker containers in real time — redact PII, run rules, alert.

    Polls matching containers every --poll-interval seconds; containers
    started later are picked up automatically. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)
    lookback = parse_lookback_utc(since)

    print_tail_header(
        [
            f"  Following : Docker — {name or label or 'all containers'}",
            f"  Interval  : {poll_interval}s   Lookback: {since}",
        ],
        no_rules=no_rules,
        alert_webhook=alert_webhook,
        alert_min_severity=alert_min_severity,
    )

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = DockerAdapter(
            name=name, label=label, include_stopped=include_stopped, since=lookback
        )
        await run_tail_pipeline(
            event_stream=adapter.poll(poll_interval),
            redactor=redactor,
            engine=engine,
            counts=counts,
            cfg=cfg,
            print_finding=print_finding,
            track_errors=track_errors,
            track_findings=track_findings,
            alert_webhook=alert_webhook,
            alert_min_severity=alert_min_severity,
        )

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    except ImportError as e:
        typer.echo(f"\nError: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"\nError talking to Docker: {e}", err=True)
        raise typer.Exit(1)

    print_tail_summary(counts, track_errors=track_errors, alert_webhook=alert_webhook)
