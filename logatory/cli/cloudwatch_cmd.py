"""CLI command group: logatory cloudwatch — analyze AWS CloudWatch Logs."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.cloudwatch import CloudWatchAdapter
from logatory.cli._pipeline import print_tail_header, print_tail_summary, run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze AWS CloudWatch Logs via the aws CLI — no boto3 needed.")


@app.command("scan")
def cloudwatch_scan(
    log_group: Annotated[str, typer.Option("--log-group", "-g", help="CloudWatch log group.")],
    log_stream: Annotated[
        Optional[str], typer.Option("--log-stream", "-s", help="Restrict to one log stream.")
    ] = None,
    filter_pattern: Annotated[
        Optional[str], typer.Option("--filter", help="CloudWatch filter pattern.")
    ] = None,
    since: Annotated[
        Optional[str], typer.Option("--since", help="Lookback window: 30s, 5m, 1h, 2d.")
    ] = None,
    region: Annotated[Optional[str], typer.Option("--region", help="AWS region.")] = None,
    profile: Annotated[Optional[str], typer.Option("--profile", help="AWS profile name.")] = None,
    max_events: Annotated[int, typer.Option("--max-events", help="Max events to fetch.")] = 1000,
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
    """Fetch events from a CloudWatch log group, redact PII, run rules.

    No boto3 dependency — events come straight through the aws CLI. Each
    event's message is parsed like any other source and tagged with its log
    group and stream.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = CloudWatchAdapter(
            log_group=log_group,
            log_stream=log_stream,
            filter_pattern=filter_pattern,
            since=since,
            region=region,
            profile=profile,
            limit=max_events,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error reading CloudWatch Logs: {e}", err=True)
        raise typer.Exit(1)

    streams = sorted({e.source for e in result.events})
    render_scan(
        result,
        source_label=f"CloudWatch ({log_group})",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=[f"  Streams    : {len(streams):,}"],
    )


@app.command("tail")
def cloudwatch_tail(
    log_group: Annotated[str, typer.Option("--log-group", "-g", help="CloudWatch log group.")],
    log_stream: Annotated[
        Optional[str], typer.Option("--log-stream", "-s", help="Restrict to one log stream.")
    ] = None,
    filter_pattern: Annotated[
        Optional[str], typer.Option("--filter", help="CloudWatch filter pattern.")
    ] = None,
    since: Annotated[
        str, typer.Option("--since", help="Initial lookback window: 30s, 5m, 1h.")
    ] = "5m",
    region: Annotated[Optional[str], typer.Option("--region", help="AWS region.")] = None,
    profile: Annotated[Optional[str], typer.Option("--profile", help="AWS profile name.")] = None,
    max_events: Annotated[
        int, typer.Option("--max-events", help="Events to fetch per poll.")
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
    """Follow a CloudWatch log group in real time — redact, run rules, alert.

    Polls the group every --poll-interval seconds, advancing a timestamp
    cursor and de-duplicating by eventId. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    print_tail_header(
        [
            f"  Following : CloudWatch — {log_group}{f' ({log_stream})' if log_stream else ''}",
            f"  Interval  : {poll_interval}s   Lookback: {since}",
        ],
        no_rules=no_rules,
        alert_webhook=alert_webhook,
        alert_min_severity=alert_min_severity,
    )

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = CloudWatchAdapter(
            log_group=log_group,
            log_stream=log_stream,
            filter_pattern=filter_pattern,
            since=since,
            region=region,
            profile=profile,
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
        typer.echo(f"\nError reading CloudWatch Logs: {e}", err=True)
        raise typer.Exit(1)

    print_tail_summary(counts, track_errors=track_errors, alert_webhook=alert_webhook)
