"""``logatory alerts`` — inspect and test configured alert channels."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.config import Config
from logatory.models import Finding, FindingSeverity
from logatory.notify import build_notifiers

app = typer.Typer(help="Inspect and test alert notification channels.")

_ConfigOpt = Annotated[
    Optional[Path],
    typer.Option("--config", "-c", help="Path to config.yaml."),
]


def _sample_finding() -> Finding:
    return Finding(
        rule_id="alerts_test",
        severity=FindingSeverity.CRITICAL,
        message="Test alert from `logatory alerts test` — your channel works.",
        source="logatory",
        timestamp=datetime.now(tz=UTC),
    )


@app.command("list")
def list_channels(config: _ConfigOpt = None) -> None:
    """List the alert channels configured under ``alerts:`` in config.yaml."""
    cfg = Config.load(config)
    try:
        notifiers = build_notifiers(cfg.alerts)
    except ValueError as exc:
        typer.secho(f"Invalid alert configuration: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    if not notifiers:
        typer.echo("No alert channels configured. Add an 'alerts:' section to config.yaml.")
        return

    typer.echo(f"{len(notifiers)} alert channel(s):")
    for n in notifiers:
        typer.echo(f"  • [{n.name}] min_severity={n.min_severity}  {n.describe()}")


@app.command("test")
def test_channels(
    config: _ConfigOpt = None,
    webhook: Annotated[
        Optional[str],
        typer.Option("--webhook", help="Also test this ad-hoc webhook URL."),
    ] = None,
) -> None:
    """Send a sample CRITICAL finding to every configured channel and report results."""
    cfg = Config.load(config)
    try:
        notifiers = build_notifiers(cfg.alerts, alert_webhook=webhook)
    except ValueError as exc:
        typer.secho(f"Invalid alert configuration: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    if not notifiers:
        typer.echo("No alert channels configured — nothing to test.")
        raise typer.Exit(code=0)

    finding = _sample_finding()
    failures = 0
    typer.echo(f"Sending a test finding to {len(notifiers)} channel(s)…")
    for n in notifiers:
        ok = n.send(finding)
        if ok:
            typer.secho(f"  ✓ [{n.name}] {n.describe()}", fg=typer.colors.GREEN)
        else:
            failures += 1
            typer.secho(f"  ✗ [{n.name}] {n.describe()} — delivery failed", fg=typer.colors.RED)

    if failures:
        raise typer.Exit(code=1)
