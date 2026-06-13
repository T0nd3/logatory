"""CLI command group: logatory ssh — analyze logs from a remote host over SSH."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.ssh import SSHAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze logs from a remote host over SSH.")


def _resolve_mode(path: Optional[str], unit: Optional[str], journald: bool) -> bool:
    """Return True for journald mode; reject an invalid path/journald combination."""
    use_journald = journald or unit is not None
    if use_journald and path:
        raise typer.BadParameter("--path cannot be combined with --journald/--unit.")
    if not use_journald and not path:
        raise typer.BadParameter(
            "specify a remote source: --path <file>, or --journald (optionally with --unit)."
        )
    return use_journald


@app.command("scan")
def ssh_scan(
    host: Annotated[
        str, typer.Argument(help="Remote host: 'user@host', 'host', or an ssh-config alias.")
    ],
    path: Annotated[Optional[str], typer.Option("--path", help="Remote log file to read.")] = None,
    unit: Annotated[
        Optional[str], typer.Option("--unit", "-u", help="Read journald, filtered to this unit.")
    ] = None,
    journald: Annotated[
        bool, typer.Option("--journald", "-j", help="Read the remote systemd journal.")
    ] = False,
    since: Annotated[
        Optional[str], typer.Option("--since", help="journald --since value, e.g. '-1h'.")
    ] = None,
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Max remote lines/entries to fetch.")
    ] = 1000,
    port: Annotated[Optional[int], typer.Option("--port", "-p", help="SSH port.")] = None,
    identity: Annotated[
        Optional[str], typer.Option("--identity", "-i", help="SSH private key file.")
    ] = None,
    ssh_opt: Annotated[
        Optional[list[str]],
        typer.Option("--ssh-opt", help="Extra 'ssh -o' option (repeatable)."),
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
    """Read logs from a remote host over SSH, redact PII, run detection rules.

    Pulls logs straight over an existing SSH connection — no agent on the
    remote box. The source is a file (--path) or the systemd journal
    (--journald / --unit). Needs an `ssh` client locally.
    """
    use_journald = _resolve_mode(path, unit, journald)
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = SSHAdapter(
            host=host,
            path=path,
            unit=unit,
            use_journald=use_journald,
            since=since,
            lines=lines,
            port=port,
            identity=identity,
            ssh_opts=ssh_opt,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error reading remote logs: {e}", err=True)
        raise typer.Exit(1)

    src_desc = f"{host} ({'journald' if use_journald else path})"
    render_scan(
        result,
        source_label=src_desc,
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
    )


@app.command("tail")
def ssh_tail(
    host: Annotated[
        str, typer.Argument(help="Remote host: 'user@host', 'host', or an ssh-config alias.")
    ],
    path: Annotated[
        Optional[str], typer.Option("--path", help="Remote log file to follow.")
    ] = None,
    unit: Annotated[
        Optional[str], typer.Option("--unit", "-u", help="Follow journald, filtered to this unit.")
    ] = None,
    journald: Annotated[
        bool, typer.Option("--journald", "-j", help="Follow the remote systemd journal.")
    ] = False,
    lines: Annotated[
        int, typer.Option("--lines", "-n", help="Entries to backfill before following.")
    ] = 20,
    reconnect_delay: Annotated[
        float, typer.Option("--reconnect-delay", help="Seconds to wait before reconnecting.")
    ] = 3.0,
    port: Annotated[Optional[int], typer.Option("--port", "-p", help="SSH port.")] = None,
    identity: Annotated[
        Optional[str], typer.Option("--identity", "-i", help="SSH private key file.")
    ] = None,
    ssh_opt: Annotated[
        Optional[list[str]],
        typer.Option("--ssh-opt", help="Extra 'ssh -o' option (repeatable)."),
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
    """Follow logs from a remote host in real time — redact PII, run rules, alert.

    Streams over a long-lived SSH connection (`journalctl -f` / `tail -F`).
    A dropped connection reconnects automatically; journald mode resumes
    gap-free via the journal cursor. Runs until Ctrl+C. Needs an `ssh` client.
    """
    use_journald = _resolve_mode(path, unit, journald)
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Following : {host} — {'journald' if use_journald else path}")
    typer.echo(f"  Reconnect : every {reconnect_delay}s on drop")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = SSHAdapter(
            host=host,
            path=path,
            unit=unit,
            use_journald=use_journald,
            lines=lines,
            port=port,
            identity=identity,
            ssh_opts=ssh_opt,
        )
        await run_tail_pipeline(
            event_stream=adapter.poll(reconnect_delay),
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
        typer.echo(f"\nError reading remote logs: {e}", err=True)
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
