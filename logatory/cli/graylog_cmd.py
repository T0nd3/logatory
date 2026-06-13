"""CLI command group: logatory graylog — analyze logs from a Graylog server."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.graylog import GraylogAdapter
from logatory.cli._pipeline import print_tail_header, print_tail_summary, run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg, parse_lookback_seconds

app = typer.Typer(help="Analyze logs from a Graylog server.")


@app.command("scan")
def graylog_scan(
    url: Annotated[
        str, typer.Option("--url", envvar="GRAYLOG_URL", help="Graylog base URL.")
    ] = "http://localhost:9000",
    query: Annotated[
        str, typer.Option("--query", "-q", help="Graylog search query ('*' = all).")
    ] = "*",
    since: Annotated[
        str, typer.Option("--since", help="Lookback window: 30s, 5m, 1h, 7d.")
    ] = "1h",
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max messages to fetch from Graylog.")
    ] = 1000,
    username: Annotated[
        Optional[str], typer.Option("--user", "-u", envvar="GRAYLOG_USERNAME")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("--password", envvar="GRAYLOG_PASSWORD")
    ] = None,
    token: Annotated[
        Optional[str],
        typer.Option("--token", envvar="GRAYLOG_TOKEN", help="Graylog access token."),
    ] = None,
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
    """Query a Graylog server, redact PII, run detection rules.

    Reads via Graylog's universal search API. Each message keeps its
    structured fields (source, level, timestamp) from Graylog.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = GraylogAdapter(
            url=url,
            query=query,
            range_seconds=parse_lookback_seconds(since),
            limit=lines,
            username=username,
            password=password,
            token=token,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error querying Graylog: {e}", err=True)
        raise typer.Exit(1)

    render_scan(
        result,
        source_label=f"Graylog {url}",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=[f"  Query      : {query}"],
    )


@app.command("tail")
def graylog_tail(
    url: Annotated[
        str, typer.Option("--url", envvar="GRAYLOG_URL", help="Graylog base URL.")
    ] = "http://localhost:9000",
    query: Annotated[
        str, typer.Option("--query", "-q", help="Graylog search query ('*' = all).")
    ] = "*",
    since: Annotated[
        str, typer.Option("--since", help="Initial lookback window: 30s, 5m, 1h.")
    ] = "5m",
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max messages to fetch per poll.")
    ] = 1000,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between Graylog queries.")
    ] = 10.0,
    username: Annotated[
        Optional[str], typer.Option("--user", "-u", envvar="GRAYLOG_USERNAME")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("--password", envvar="GRAYLOG_PASSWORD")
    ] = None,
    token: Annotated[
        Optional[str],
        typer.Option("--token", envvar="GRAYLOG_TOKEN", help="Graylog access token."),
    ] = None,
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
    """Poll a Graylog server in real time — redact PII, run rules, alert.

    Searches Graylog every --poll-interval seconds for newly-arrived
    messages, resuming from the last message timestamp. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    print_tail_header(
        [
            f"  Polling   : Graylog {url}",
            f"  Query     : {query}",
            f"  Interval  : {poll_interval}s   Lookback: {since}",
        ],
        no_rules=no_rules,
        alert_webhook=alert_webhook,
        alert_min_severity=alert_min_severity,
    )

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = GraylogAdapter(
            url=url,
            query=query,
            range_seconds=parse_lookback_seconds(since),
            limit=lines,
            username=username,
            password=password,
            token=token,
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
        typer.echo(f"\nError querying Graylog: {e}", err=True)
        raise typer.Exit(1)

    print_tail_summary(counts, track_errors=track_errors, alert_webhook=alert_webhook)
