"""CLI command group: logatory windows — analyze Windows Event Log exports."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.windows import WindowsEventLogAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze Windows Event Log JSON exports (or live via PowerShell).")


def _make_adapter(
    path: Optional[Path], log: Optional[str], provider: Optional[str], max_events: int
) -> WindowsEventLogAdapter:
    return WindowsEventLogAdapter(
        path=path,
        log=log,
        provider=provider,
        max_events=max_events,
    )


@app.command("scan")
def windows_scan(
    path: Annotated[
        Optional[Path], typer.Option("--path", "-f", help="Path to a JSON event export.")
    ] = None,
    log: Annotated[
        Optional[str],
        typer.Option("--log", "-L", help="Live log name via PowerShell, e.g. System."),
    ] = None,
    provider: Annotated[
        Optional[str], typer.Option("--provider", help="Provider name filter (live mode).")
    ] = None,
    max_events: Annotated[
        int, typer.Option("--max-events", help="Max events to fetch in live mode.")
    ] = 200,
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
    """Analyze a Windows Event Log JSON export, redact PII, run detection rules.

    Provide either a JSON export with --path (portable, works on Linux) or a
    live log name with --log (Windows only, shells out to Get-WinEvent).
    """
    if path is None and log is None:
        typer.echo("Error: provide either --path <export.json> or --log <LogName>.", err=True)
        raise typer.Exit(2)

    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = _make_adapter(path, log, provider, max_events)
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error reading Windows events: {e}", err=True)
        raise typer.Exit(1)

    sources = sorted({e.source for e in result.events})
    render_scan(
        result,
        source_label=f"Windows ({path or log})",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=[f"  Providers  : {', '.join(sources[:10])}"] if sources else None,
    )


@app.command("tail")
def windows_tail(
    log: Annotated[
        str, typer.Option("--log", "-L", help="Live log name via PowerShell, e.g. System.")
    ],
    provider: Annotated[
        Optional[str], typer.Option("--provider", help="Provider name filter.")
    ] = None,
    max_events: Annotated[
        int, typer.Option("--max-events", help="Events to fetch per poll.")
    ] = 200,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between polls.")
    ] = 5.0,
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
    """Follow a live Windows Event Log in real time (Windows only).

    Polls the log every --poll-interval seconds, de-duplicating by RecordId so
    each event is delivered once. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Following : Windows log — {log}{f' ({provider})' if provider else ''}")
    typer.echo(f"  Interval  : {poll_interval}s")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = WindowsEventLogAdapter(log=log, provider=provider, max_events=max_events)
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
    except Exception as e:
        typer.echo(f"\nError reading Windows events: {e}", err=True)
        raise typer.Exit(1)

    typer.echo(f"\n{sep}")
    typer.echo("  Stopped.")
    typer.echo(f"  Events   : {counts['events']:,}")
    typer.echo(f"  PII hits : {counts['pii']:,}")
    typer.echo(f"  Findings : {counts['findings']:,}")
    if track_errors:
        typer.echo(f"  Errors   : {counts['errors']:,} tracked")
    if alert_webhook:
        typer.echo(f"  Webhooks : {counts['webhooks']:,} sent")
    typer.echo(sep)
