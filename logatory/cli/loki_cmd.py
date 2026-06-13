"""CLI command group: logatory loki — analyze logs from a Grafana Loki instance."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.loki import LokiAdapter
from logatory.cli._pipeline import print_tail_header, print_tail_summary, run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg, parse_lookback_seconds

app = typer.Typer(help="Analyze logs from a Grafana Loki instance.")

_NS_PER_SECOND = 1_000_000_000


def _start_ns(since: str) -> int:
    now_ns = int(datetime.now(tz=UTC).timestamp()) * _NS_PER_SECOND
    return now_ns - parse_lookback_seconds(since) * _NS_PER_SECOND


@app.command("scan")
def loki_scan(
    url: Annotated[
        str, typer.Option("--url", envvar="LOKI_URL", help="Loki base URL.")
    ] = "http://localhost:3100",
    query: Annotated[
        str, typer.Option("--query", "-q", help="LogQL stream selector.")
    ] = '{job=~".+"}',
    since: Annotated[
        str, typer.Option("--since", help="Lookback window: 30s, 5m, 1h, 7d.")
    ] = "1h",
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max entries to fetch from Loki.")
    ] = 1000,
    source_label: Annotated[
        str, typer.Option("--source-label", help="Stream label used as the event source.")
    ] = "job",
    username: Annotated[
        Optional[str], typer.Option("--user", "-u", envvar="LOKI_USERNAME")
    ] = None,
    password: Annotated[Optional[str], typer.Option("--password", envvar="LOKI_PASSWORD")] = None,
    token: Annotated[
        Optional[str], typer.Option("--token", envvar="LOKI_TOKEN", help="Bearer token.")
    ] = None,
    org_id: Annotated[
        Optional[str], typer.Option("--org-id", envvar="LOKI_ORG_ID", help="X-Scope-OrgID tenant.")
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
    """Query a Grafana Loki instance, redact PII, run detection rules.

    Reads via Loki's `query_range` API with a LogQL selector. Each log
    line is parsed by format detection, just like a local file.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = LokiAdapter(
            url=url,
            query=query,
            start_ns=_start_ns(since),
            limit=lines,
            source_label=source_label,
            username=username,
            password=password,
            token=token,
            org_id=org_id,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error querying Loki: {e}", err=True)
        raise typer.Exit(1)

    render_scan(
        result,
        source_label=f"Loki {url}",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=[f"  Query      : {query}"],
    )


@app.command("tail")
def loki_tail(
    url: Annotated[
        str, typer.Option("--url", envvar="LOKI_URL", help="Loki base URL.")
    ] = "http://localhost:3100",
    query: Annotated[
        str, typer.Option("--query", "-q", help="LogQL stream selector.")
    ] = '{job=~".+"}',
    since: Annotated[
        str, typer.Option("--since", help="Initial lookback window: 30s, 5m, 1h.")
    ] = "5m",
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max entries to fetch per poll.")
    ] = 1000,
    source_label: Annotated[
        str, typer.Option("--source-label", help="Stream label used as the event source.")
    ] = "job",
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between Loki queries.")
    ] = 10.0,
    username: Annotated[
        Optional[str], typer.Option("--user", "-u", envvar="LOKI_USERNAME")
    ] = None,
    password: Annotated[Optional[str], typer.Option("--password", envvar="LOKI_PASSWORD")] = None,
    token: Annotated[
        Optional[str], typer.Option("--token", envvar="LOKI_TOKEN", help="Bearer token.")
    ] = None,
    org_id: Annotated[
        Optional[str], typer.Option("--org-id", envvar="LOKI_ORG_ID", help="X-Scope-OrgID tenant.")
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
    """Poll a Grafana Loki instance in real time — redact PII, run rules, alert.

    Queries `query_range` every --poll-interval seconds for newly-arrived
    entries, resuming from Loki's nanosecond timestamp. Runs until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    print_tail_header(
        [
            f"  Polling   : Loki {url}",
            f"  Query     : {query}",
            f"  Interval  : {poll_interval}s   Lookback: {since}",
        ],
        no_rules=no_rules,
        alert_webhook=alert_webhook,
        alert_min_severity=alert_min_severity,
    )

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = LokiAdapter(
            url=url,
            query=query,
            start_ns=_start_ns(since),
            limit=lines,
            source_label=source_label,
            username=username,
            password=password,
            token=token,
            org_id=org_id,
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
        typer.echo(f"\nError querying Loki: {e}", err=True)
        raise typer.Exit(1)

    print_tail_summary(counts, track_errors=track_errors, alert_webhook=alert_webhook)
