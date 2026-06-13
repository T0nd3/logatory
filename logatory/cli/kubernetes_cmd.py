"""CLI command group: logatory kubernetes — analyze logs from cluster pods."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.kubernetes import KubernetesAdapter
from logatory.cli._pipeline import print_tail_header, print_tail_summary, run_tail_pipeline
from logatory.cli._scan import ScanResult, build_pipeline, collect_scan, print_finding, render_scan
from logatory.cli._types import RedactModeArg

app = typer.Typer(help="Analyze logs from Kubernetes pods via kubectl — no log stack needed.")


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
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    async def _run() -> ScanResult:
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
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error talking to Kubernetes: {e}", err=True)
        raise typer.Exit(1)

    pods = sorted({e.source for e in result.events})
    render_scan(
        result,
        source_label=f"Kubernetes ({len(pods)} container(s))",
        redact_mode=redact.value,
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        track_errors=track_errors,
        extra_lines=[f"  Pods       : {', '.join(pods)}"] if pods else None,
    )


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
    cfg, redactor, engine = build_pipeline(config, redact, no_rules, rules_dir)

    print_tail_header(
        [
            f"  Following : Kubernetes — {selector or pod or namespace or 'all pods'}",
            f"  Interval  : {poll_interval}s   Lookback: {since}",
        ],
        no_rules=no_rules,
        alert_webhook=alert_webhook,
        alert_min_severity=alert_min_severity,
    )

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
        typer.echo(f"\nError talking to Kubernetes: {e}", err=True)
        raise typer.Exit(1)

    print_tail_summary(counts, track_errors=track_errors, alert_webhook=alert_webhook)
