"""CLI command group: logatory kubernetes — analyze logs from cluster pods."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.kubernetes import KubernetesAdapter
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.cli.colors import SEVERITY_COLOR
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.models import Event, Finding
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import compile_plugin_pii_patterns, load_plugins
from logatory.rules.loader import build_engine
from logatory.storage.errors_repo import ErrorsRepository

app = typer.Typer(help="Analyze logs from Kubernetes pods via kubectl — no log stack needed.")


def _print_finding(finding: Finding) -> None:
    color = SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    line = f"  [{finding.severity.value.upper()}] {ts}  {finding.rule_id}  {finding.message}"
    typer.echo(typer.style(line, fg=color))


@app.command("scan")
def kubernetes_scan(
    namespace: Annotated[
        Optional[str], typer.Option("--namespace", "-n", help="Namespace to read pods from.")
    ] = None,
    selector: Annotated[
        Optional[str], typer.Option("--selector", "-l", help="Label selector, e.g. 'app=api'.")
    ] = None,
    pod: Annotated[
        Optional[str], typer.Option("--pod", "-p", help="A single pod name to read.")
    ] = None,
    container: Annotated[
        Optional[str], typer.Option("--container", "-c", help="Restrict to one container.")
    ] = None,
    all_namespaces: Annotated[
        bool, typer.Option("--all-namespaces", "-A", help="Read pods across all namespaces.")
    ] = False,
    tail: Annotated[int, typer.Option("--tail", help="Log lines to fetch per container.")] = 200,
    since: Annotated[
        Optional[str], typer.Option("--since", help="Lookback window: 30s, 5m, 1h.")
    ] = None,
    context: Annotated[
        Optional[str], typer.Option("--context", help="kubeconfig context to use.")
    ] = None,
    kubeconfig: Annotated[
        Optional[str], typer.Option("--kubeconfig", help="Path to a kubeconfig file.")
    ] = None,
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
    """Fetch logs from Kubernetes pods, redact PII, run detection rules.

    No log-aggregation stack required — logs come straight through kubectl.
    Each event is tagged with its namespace, pod and container.
    """
    cfg = Config.load(config)

    plugin_registry = load_plugins(cfg.plugins_dir)
    plugin_pii = compile_plugin_pii_patterns(plugin_registry)
    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=REDACT_MAP[redact],
        additional=plugin_pii or None,
    )

    engine = build_engine(no_rules, rules_dir, plugin_registry)

    events: list[Event] = []
    findings: list[Finding] = []
    pii_hits = 0

    async def _run() -> None:
        nonlocal pii_hits
        adapter = KubernetesAdapter(
            namespace=namespace,
            selector=selector,
            pod=pod,
            container=container,
            all_namespaces=all_namespaces,
            tail=tail,
            since=since,
            context=context,
            kubeconfig=kubeconfig,
        )
        async for event in adapter.events():
            result = redactor.redact(event.message)
            event.message = result.text
            event.raw = redactor.redact(event.raw).text
            pii_hits += len(result.hits)
            events.append(event)
            if engine:
                findings.extend(engine.process(event))

    try:
        asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error talking to Kubernetes: {e}", err=True)
        raise typer.Exit(1)

    pods = sorted({e.source for e in events})
    sep = "-" * 60
    typer.echo(
        f"\n{sep}\n"
        f"  Source     : Kubernetes ({len(pods)} container(s))\n"
        f"  Events     : {len(events):,}\n"
        f"  PII hits   : {pii_hits:,} (mode: {redact.value})\n"
        f"  Findings   : {len(findings):,}\n"
        f"{sep}"
    )
    if pods:
        typer.echo(f"  Pods       : {', '.join(pods)}")

    sample = events if show_all else events[:limit]
    if sample:
        typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
        for i, ev in enumerate(sample, 1):
            ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "no timestamp"
            sev = ev.severity.value.upper().ljust(8)
            typer.echo(f"  [{i:>5}] {ts}  {sev}  {ev.source}  {ev.message[:100]}")
        if not show_all and len(events) > limit:
            typer.echo(f"\n  ... {len(events) - limit:,} more. Use --show-all or --limit N.")

    if findings:
        typer.echo(f"\n  Findings ({len(findings)}):\n")
        for finding in findings:
            _print_finding(finding)
    elif not no_rules:
        typer.echo("\n  No findings.")

    if track_errors and events:
        with ErrorsRepository(cfg.db_path) as e_repo:
            tracker = ErrorTracker(e_repo)
            tracked = sum(1 for ev in events if tracker.process(ev) is not None)
        typer.echo(f"\n  Errors tracked: {tracked:,} -> {cfg.db_path}")


@app.command("tail")
def kubernetes_tail(
    namespace: Annotated[
        Optional[str], typer.Option("--namespace", "-n", help="Namespace to read pods from.")
    ] = None,
    selector: Annotated[
        Optional[str], typer.Option("--selector", "-l", help="Label selector, e.g. 'app=api'.")
    ] = None,
    pod: Annotated[
        Optional[str], typer.Option("--pod", "-p", help="A single pod name to follow.")
    ] = None,
    container: Annotated[
        Optional[str], typer.Option("--container", "-c", help="Restrict to one container.")
    ] = None,
    all_namespaces: Annotated[
        bool, typer.Option("--all-namespaces", "-A", help="Follow pods across all namespaces.")
    ] = False,
    since: Annotated[
        str, typer.Option("--since", help="Initial lookback window: 30s, 5m, 1h.")
    ] = "1m",
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between polls.")
    ] = 3.0,
    context: Annotated[
        Optional[str], typer.Option("--context", help="kubeconfig context to use.")
    ] = None,
    kubeconfig: Annotated[
        Optional[str], typer.Option("--kubeconfig", help="Path to a kubeconfig file.")
    ] = None,
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
    """Follow Kubernetes pods in real time — redact PII, run rules, alert.

    Polls matching pods every --poll-interval seconds; pods scheduled later
    are picked up automatically. Runs until Ctrl+C.
    """
    cfg = Config.load(config)

    plugin_registry = load_plugins(cfg.plugins_dir)
    plugin_pii = compile_plugin_pii_patterns(plugin_registry)
    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=REDACT_MAP[redact],
        additional=plugin_pii or None,
    )

    engine = build_engine(no_rules, rules_dir, plugin_registry)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Following : Kubernetes — {selector or pod or namespace or 'all pods'}")
    typer.echo(f"  Interval  : {poll_interval}s   Lookback: {since}")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = KubernetesAdapter(
            namespace=namespace,
            selector=selector,
            pod=pod,
            container=container,
            all_namespaces=all_namespaces,
            since=since,
            context=context,
            kubeconfig=kubeconfig,
        )
        await run_tail_pipeline(
            event_stream=adapter.poll(poll_interval),
            redactor=redactor,
            engine=engine,
            counts=counts,
            cfg=cfg,
            print_finding=_print_finding,
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
        typer.echo(f"\nError talking to Kubernetes: {e}", err=True)
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
