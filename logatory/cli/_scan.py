"""Shared building blocks for the one-shot ``logatory <source> scan`` commands.

Every ``logatory <source> scan`` used to re-implement the same ~85 lines: load
the config, build a redactor from config + plugins, build the rule engine, drain
the adapter while redacting and running rules, then print an identical summary,
event listing and findings section (plus optional error tracking).

This module factors that out:

* :func:`build_pipeline`  — config + redactor + engine setup (also used by tail).
* :func:`collect_scan`    — the async redact + rules loop, returning a result.
* :func:`render_scan`     — the summary / events / findings / track-errors output.
* :func:`print_finding`   — the single coloured finding formatter.

Each ``scan`` command then only declares its own options, builds its adapter,
and calls these — shrinking the per-source modules by well over half.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.cli.colors import SEVERITY_COLOR
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import compile_plugin_pii_patterns, load_plugins
from logatory.rules.loader import build_engine
from logatory.storage.errors_repo import ErrorsRepository

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from logatory.models import Event, Finding
    from logatory.rules.engine import RuleEngine

_SEP = "-" * 60


@dataclass
class ScanResult:
    """Accumulated output of a one-shot scan."""

    events: list[Event] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pii_hits: int = 0


def build_pipeline(
    config: Path | None,
    redact: RedactModeArg,
    no_rules: bool,
    rules_dir: Path | None,
) -> tuple[Config, PIIRedactor, RuleEngine | None]:
    """Load config and build the redactor + rule engine (plugins included)."""
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
    return cfg, redactor, engine


async def collect_scan(
    event_stream: AsyncIterator[Event],
    redactor: PIIRedactor,
    engine: RuleEngine | None,
    *,
    result: ScanResult | None = None,
) -> ScanResult:
    """Drain *event_stream*, redacting PII and running rules; return the result.

    Pass an existing *result* to have it filled in place — useful when the caller
    wants to render whatever was collected so far after a ``KeyboardInterrupt``.
    """
    if result is None:
        result = ScanResult()
    async for event in event_stream:
        redacted = redactor.redact(event.message)
        event.message = redacted.text
        event.raw = redactor.redact(event.raw).text
        result.pii_hits += len(redacted.hits)
        result.events.append(event)
        if engine:
            result.findings.extend(engine.process(event))
    return result


def print_finding(finding: Finding) -> None:
    """Print one finding in the shared coloured one-line format."""
    color = SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    line = f"  [{finding.severity.value.upper()}] {ts}  {finding.rule_id}  {finding.message}"
    typer.echo(typer.style(line, fg=color))


def _event_line(i: int, ev: Event, *, msg_width: int, show_source: bool) -> str:
    ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "no timestamp"
    sev = ev.severity.value.upper().ljust(8)
    src = f"{ev.source}  " if show_source else ""
    return f"  [{i:>5}] {ts}  {sev}  {src}{ev.message[:msg_width]}"


def render_scan(
    result: ScanResult,
    *,
    source_label: str,
    redact_mode: str,
    limit: int,
    show_all: bool,
    no_rules: bool,
    cfg: Config,
    track_errors: bool = False,
    extra_lines: list[str] | None = None,
    msg_width: int = 100,
    show_source: bool = True,
) -> None:
    """Print the standard scan summary, event listing and findings section."""
    events, findings = result.events, result.findings
    typer.echo(
        f"\n{_SEP}\n"
        f"  Source     : {source_label}\n"
        f"  Events     : {len(events):,}\n"
        f"  PII hits   : {result.pii_hits:,} (mode: {redact_mode})\n"
        f"  Findings   : {len(findings):,}\n"
        f"{_SEP}"
    )
    for line in extra_lines or []:
        typer.echo(line)

    sample = events if show_all else events[:limit]
    if sample:
        typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
        for i, ev in enumerate(sample, 1):
            typer.echo(_event_line(i, ev, msg_width=msg_width, show_source=show_source))
        if not show_all and len(events) > limit:
            typer.echo(f"\n  ... {len(events) - limit:,} more. Use --show-all or --limit N.")

    if findings:
        typer.echo(f"\n  Findings ({len(findings)}):\n")
        for finding in findings:
            print_finding(finding)
    elif not no_rules:
        typer.echo("\n  No findings.")

    if track_errors and events:
        with ErrorsRepository(cfg.db_path) as e_repo:
            tracker = ErrorTracker(e_repo)
            tracked = sum(1 for ev in events if tracker.process(ev) is not None)
        typer.echo(f"\n  Errors tracked: {tracked:,} -> {cfg.db_path}")
