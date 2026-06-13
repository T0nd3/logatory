"""CLI command group: logatory s3 — analyze logs from S3 / object storage."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.s3 import S3Adapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze logs stored in S3 / object storage via the aws CLI.")


@app.command("scan")
def s3_scan(
    bucket: Annotated[str, typer.Option("--bucket", "-b", help="Bucket name.")],
    prefix: Annotated[
        Optional[str], typer.Option("--prefix", "-p", help="Key prefix to filter objects.")
    ] = None,
    endpoint_url: Annotated[
        Optional[str],
        typer.Option("--endpoint-url", help="Custom endpoint for S3-compatible stores."),
    ] = None,
    region: Annotated[Optional[str], typer.Option("--region", help="AWS region.")] = None,
    profile: Annotated[Optional[str], typer.Option("--profile", help="AWS profile name.")] = None,
    max_objects: Annotated[int, typer.Option("--max-objects", help="Max objects to read.")] = 50,
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
    """Read log objects from a bucket, redact PII, run detection rules.

    Streams each object straight through the aws CLI — gzip objects are
    decompressed transparently. Each event is tagged with its bucket and key.
    Point --endpoint-url at MinIO/R2/B2/etc. to read S3-compatible stores.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = S3Adapter(
            bucket=bucket,
            prefix=prefix,
            endpoint_url=endpoint_url,
            region=region,
            profile=profile,
            max_objects=max_objects,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error reading from S3: {e}", err=True)
        raise typer.Exit(1)

    keys = sorted({e.source for e in result.events})
    extra = [f"  Objects    : {len(keys):,}"]
    if keys:
        extra.append(f"  Keys       : {', '.join(keys[:10])}")
    render_scan(
        result,
        source_label=f"S3 ({bucket}{'/' + prefix if prefix else ''})",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=extra,
    )


@app.command("tail")
def s3_tail(
    bucket: Annotated[str, typer.Option("--bucket", "-b", help="Bucket name.")],
    prefix: Annotated[
        Optional[str], typer.Option("--prefix", "-p", help="Key prefix to filter objects.")
    ] = None,
    endpoint_url: Annotated[
        Optional[str],
        typer.Option("--endpoint-url", help="Custom endpoint for S3-compatible stores."),
    ] = None,
    region: Annotated[Optional[str], typer.Option("--region", help="AWS region.")] = None,
    profile: Annotated[Optional[str], typer.Option("--profile", help="AWS profile name.")] = None,
    max_objects: Annotated[
        int, typer.Option("--max-objects", help="Max objects to list per poll.")
    ] = 50,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between polls.")
    ] = 30.0,
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
    """Watch a bucket for new log objects in real time — redact, run rules, alert.

    Polls the bucket every --poll-interval seconds; objects are immutable in
    S3, so each new key is read exactly once. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Watching  : s3://{bucket}{'/' + prefix if prefix else ''}")
    typer.echo(f"  Interval  : {poll_interval}s")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = S3Adapter(
            bucket=bucket,
            prefix=prefix,
            endpoint_url=endpoint_url,
            region=region,
            profile=profile,
            max_objects=max_objects,
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
        typer.echo(f"\nError reading from S3: {e}", err=True)
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
