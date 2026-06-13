"""CLI command group: logatory syslog — receive syslog over UDP/TCP."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.syslog_listener import SyslogListenerAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Receive syslog over UDP/TCP (RFC 3164 / RFC 5424) and analyze it.")


@app.command("scan")
def syslog_scan(
    host: Annotated[str, typer.Option("--host", "-H", help="Address to bind.")] = "0.0.0.0",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to bind.")] = 514,
    protocol: Annotated[
        str, typer.Option("--protocol", help="Transport: udp, tcp or both.")
    ] = "udp",
    max_messages: Annotated[
        int, typer.Option("--max-messages", help="Stop after this many messages.")
    ] = 100,
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
    """Collect a bounded batch of syslog messages, redact PII, run rules.

    Binds the port, waits for up to --max-messages messages, then summarizes.
    Use `syslog listen` to follow indefinitely.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    typer.echo(
        f"Listening on {protocol}://{host}:{port} for up to {max_messages} messages "
        "(Ctrl+C to stop early)…"
    )

    result = ScanResult()

    async def _run() -> None:
        adapter = SyslogListenerAdapter(
            host=host, port=port, protocol=protocol, max_messages=max_messages
        )
        await collect_scan(adapter.events(), redactor, engine, result=result)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass  # render whatever was collected before Ctrl+C
    except Exception as e:
        typer.echo(f"Error receiving syslog: {e}", err=True)
        raise typer.Exit(1)

    hosts = sorted({e.source for e in result.events})
    extra = [f"  Hosts      : {len(hosts):,}"]
    if hosts:
        extra.append(f"  Senders    : {', '.join(hosts[:10])}")
    render_scan(
        result,
        source_label=f"Syslog ({protocol}://{host}:{port})",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=extra,
    )


@app.command("listen")
def syslog_listen(
    host: Annotated[str, typer.Option("--host", "-H", help="Address to bind.")] = "0.0.0.0",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to bind.")] = 514,
    protocol: Annotated[
        str, typer.Option("--protocol", help="Transport: udp, tcp or both.")
    ] = "udp",
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
    """Receive syslog in real time — redact PII, run rules, alert.

    Binds the UDP/TCP port and processes every incoming message until Ctrl+C.
    """
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Listening : syslog {protocol}://{host}:{port}")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = SyslogListenerAdapter(host=host, port=port, protocol=protocol)
        await run_tail_pipeline(
            event_stream=adapter.poll(),
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
        typer.echo(f"\nError receiving syslog: {e}", err=True)
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
