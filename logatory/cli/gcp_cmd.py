"""CLI command group: logatory gcp — analyze GCP Cloud Logging entries."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.gcp_logging import GCPLoggingAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze GCP Cloud Logging entries via the gcloud CLI.")


@app.command("scan")
def gcp_scan(
    log_filter: Annotated[
        Optional[str], typer.Option("--filter", "-f", help="Cloud Logging filter expression.")
    ] = None,
    project: Annotated[
        Optional[str], typer.Option("--project", "-p", help="GCP project ID.")
    ] = None,
    since: Annotated[str, typer.Option("--since", help="Freshness window: 1h, 30m, 2d.")] = "1h",
    max_events: Annotated[int, typer.Option("--max-events", help="Max entries to fetch.")] = 1000,
    config: Annotated[Optional[Path], typer.Option("--config")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    limit: Annotated[int, typer.Option("--limit", help="Max events to display.")] = 50,
    show_all: Annotated[bool, typer.Option("--show-all", help="Display every event.")] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
) -> None:
    """Fetch entries from GCP Cloud Logging, redact PII, run detection rules.

    No google-cloud dependency — entries come straight through `gcloud
    logging read`. Severity and timestamp come from the entry itself.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = GCPLoggingAdapter(
            log_filter=log_filter,
            project=project,
            since=since,
            limit=max_events,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error reading Cloud Logging: {e}", err=True)
        raise typer.Exit(1)

    resources = sorted({e.source for e in result.events})
    extra = [f"  Resources  : {len(resources):,}"]
    if resources:
        extra.append(f"  Resources  : {', '.join(resources[:10])}")
    render_scan(
        result,
        source_label=f"GCP Cloud Logging ({project or 'default project'})",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=extra,
    )


@app.command("tail")
def gcp_tail(
    log_filter: Annotated[
        Optional[str], typer.Option("--filter", "-f", help="Cloud Logging filter expression.")
    ] = None,
    project: Annotated[
        Optional[str], typer.Option("--project", "-p", help="GCP project ID.")
    ] = None,
    since: Annotated[
        str, typer.Option("--since", help="Initial freshness window: 1h, 30m.")
    ] = "5m",
    max_events: Annotated[
        int, typer.Option("--max-events", help="Entries to fetch per poll.")
    ] = 1000,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between polls.")
    ] = 10.0,
    config: Annotated[Optional[Path], typer.Option("--config")] = None,
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
    """Follow GCP Cloud Logging in real time — redact, run rules, alert.

    Polls every --poll-interval seconds, AND-ing a timestamp clause onto the
    filter and de-duplicating by insertId. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Following : GCP Cloud Logging — {log_filter or 'all entries'}")
    typer.echo(f"  Project   : {project or 'default'}   Interval: {poll_interval}s")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = GCPLoggingAdapter(
            log_filter=log_filter,
            project=project,
            since=since,
            limit=max_events,
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
    except Exception as e:
        typer.echo(f"\nError reading Cloud Logging: {e}", err=True)
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
