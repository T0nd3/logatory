"""CLI command group: logatory journald — analyze logs from the systemd journal."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.journald import JournaldAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze logs from the systemd journal (journald).")


@app.command("scan")
def journald_scan(
    unit: Annotated[
        Optional[str],
        typer.Option("--unit", "-u", help="Filter by systemd unit, e.g. nginx.service."),
    ] = None,
    since: Annotated[
        Optional[str],
        typer.Option("--since", help="journalctl --since value, e.g. 'today', '-1h'."),
    ] = None,
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max journal entries to fetch.")
    ] = 1000,
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
    """Read the systemd journal, redact PII, run detection rules.

    Needs `journalctl` — a systemd-based Linux system.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = JournaldAdapter(unit=unit, since=since, lines=lines)
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error reading the journal: {e}", err=True)
        raise typer.Exit(1)

    units = sorted({e.source for e in result.events})
    render_scan(
        result,
        source_label=f"systemd journal ({len(units)} unit(s))",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
    )


@app.command("tail")
def journald_tail(
    unit: Annotated[
        Optional[str], typer.Option("--unit", "-u", help="Filter by systemd unit.")
    ] = None,
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Entries to show before following.")
    ] = 20,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between journal polls.")
    ] = 2.0,
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
    """Follow the systemd journal in real time — redact PII, run rules, alert.

    Polls journald every --poll-interval seconds via its native cursor.
    Runs until Ctrl+C. Needs `journalctl`.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Following : systemd journal — {unit or 'all units'}")
    typer.echo(f"  Interval  : {poll_interval}s")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = JournaldAdapter(unit=unit, lines=lines)
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
        typer.echo(f"\nError reading the journal: {e}", err=True)
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
