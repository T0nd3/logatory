"""CLI command group: logatory fleet — analyze logs from multiple targets at once."""

from __future__ import annotations

import asyncio
import queue
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml

from logatory.adapters.base import SourceAdapter
from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.cli.colors import SEVERITY_COLOR
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.fleet import (
    TYPE_FIELDS,
    Target,
    TargetConfigError,
    build_adapter,
    load_targets,
    select_targets,
)
from logatory.models import Event, Finding, Severity
from logatory.notify import build_notifiers, dispatch
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import compile_plugin_pii_patterns, load_plugins
from logatory.rules.loader import build_engine
from logatory.storage.dismiss_repo import DismissRepository
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository, meets_min_severity

app = typer.Typer(help="Analyze logs from multiple configured targets — a fleet.")


@app.callback()
def fleet() -> None:
    """Analyze logs from multiple configured targets — a fleet."""
    # Keeps `fleet` a command group (so `fleet scan` needs the subcommand name)
    # even while it has only one command.


@dataclass
class _FetchResult:
    """Raw events pulled from one target, plus any failure."""

    target: Target
    events: list[Event]
    error: str | None


def _fetch_target(target: Target) -> _FetchResult:
    """Drain one target's adapter. Runs in a worker thread; never raises."""
    events: list[Event] = []
    try:
        adapter = build_adapter(target)

        async def _drain() -> None:
            async for event in adapter.events():
                event.parsed_fields["target"] = target.name
                events.append(event)

        asyncio.run(_drain())
        return _FetchResult(target, events, None)
    except Exception as e:
        # failure isolation — one dead target must not abort the fleet scan
        return _FetchResult(target, events, str(e))


def _print_summary(
    summaries: list[tuple[str, str, int, int, str]],
    total_events: int,
    pii_hits: int,
    total_findings: int,
    redact: RedactModeArg,
) -> None:
    name_w = max([len("TARGET")] + [len(s[0]) for s in summaries])
    sep = "  " + "-" * 66
    typer.echo(sep)
    header = f"  {'TARGET'.ljust(name_w)}  {'STATUS'.ljust(8)}  {'EVENTS':>9}  {'FINDINGS':>9}"
    typer.echo(header)
    typer.echo(sep)

    ok = failed = 0
    for name, status, ev_count, f_count, detail in summaries:
        if status == "ok":
            ok += 1
            status_str = typer.style("ok".ljust(8), fg=typer.colors.GREEN)
        else:
            failed += 1
            status_str = typer.style("failed".ljust(8), fg=typer.colors.RED)
        typer.echo(f"  {name.ljust(name_w)}  {status_str}  {ev_count:>9,}  {f_count:>9,}")
        if detail:
            typer.echo(f"  {' ' * name_w}  └─ {detail[:60]}")

    typer.echo(sep)
    typer.echo(
        f"  {ok} ok · {failed} failed   ·   events {total_events:,}   ·   "
        f"PII {pii_hits:,} ({redact.value})   ·   findings {total_findings:,}"
    )
    typer.echo(sep)


def _print_events(events: list[Event], limit: int, show_all: bool) -> None:
    sample = events if show_all else events[:limit]
    if not sample:
        return
    typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
    for i, ev in enumerate(sample, 1):
        ts = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "no timestamp"
        sev = ev.severity.value.upper().ljust(8)
        tgt = str(ev.parsed_fields.get("target", "?"))
        typer.echo(f"  [{i:>5}] {ts}  {sev}  {tgt}  {ev.message[:90]}")
    if not show_all and len(events) > limit:
        typer.echo(f"\n  ... {len(events) - limit:,} more. Use --show-all or --limit N.")


def _print_finding(target_name: str, finding: Finding) -> None:
    color = SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    line = (
        f"  [{finding.severity.value.upper()}] {ts}  {target_name}  "
        f"{finding.rule_id}  {finding.message}"
    )
    typer.echo(typer.style(line, fg=color))


def _print_findings(findings: list[tuple[str, Finding]], no_rules: bool) -> None:
    if findings:
        typer.echo(f"\n  Findings ({len(findings)}):\n")
        for target_name, finding in findings:
            _print_finding(target_name, finding)
    elif not no_rules:
        typer.echo("\n  No findings.")


@app.command("scan")
def fleet_scan(
    targets_file: Annotated[Path, typer.Option("--targets", help="Targets file to load.")] = Path(
        "targets.yaml"
    ),
    target: Annotated[
        Optional[list[str]],
        typer.Option("--target", help="Select a target by name (repeatable)."),
    ] = None,
    group: Annotated[
        Optional[list[str]],
        typer.Option("--group", help="Select targets by group (repeatable)."),
    ] = None,
    workers: Annotated[
        int, typer.Option("--workers", help="Max targets fetched concurrently.")
    ] = 16,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    limit: Annotated[int, typer.Option("--limit", help="Max events to display.")] = 50,
    show_all: Annotated[bool, typer.Option("--show-all", help="Display every event.")] = False,
    findings_only: Annotated[
        bool, typer.Option("--findings-only", help="Skip the events list.")
    ] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip the rule engine.")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite.")
    ] = False,
) -> None:
    """Scan every configured target once, concurrently — redact PII, run rules.

    Reads a targets file (default: targets.yaml). Targets are fetched in
    parallel; a target that fails is reported but does not abort the run.
    """
    try:
        selected = select_targets(load_targets(targets_file), target, group)
    except TargetConfigError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

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

    typer.echo(f"\n  Fleet scan — {len(selected)} target(s), fetching concurrently...")

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(selected)))) as pool:
        results = list(pool.map(_fetch_target, selected))

    # Pipeline runs serially on the main thread — the rule engine and error
    # tracker keep mutable state and are not safe to share across threads.
    events: list[Event] = []
    findings: list[tuple[str, Finding]] = []
    summaries: list[tuple[str, str, int, int, str]] = []
    pii_hits = 0
    errors_tracked = 0

    e_repo: ErrorsRepository | None = None
    tracker: ErrorTracker | None = None
    if track_errors:
        e_repo = ErrorsRepository(cfg.db_path)
        e_repo.open()
        tracker = ErrorTracker(e_repo)

    try:
        for r in results:
            t_events = 0
            t_findings = 0
            for ev in r.events:
                result = redactor.redact(ev.message)
                ev.message = result.text
                ev.raw = redactor.redact(ev.raw).text
                pii_hits += len(result.hits)
                events.append(ev)
                t_events += 1
                if engine:
                    for finding in engine.process(ev):
                        findings.append((r.target.name, finding))
                        t_findings += 1
                if tracker and tracker.process(ev) is not None:
                    errors_tracked += 1
            status = "ok" if r.error is None else "failed"
            summaries.append((r.target.name, status, t_events, t_findings, r.error or ""))
    finally:
        if e_repo:
            e_repo.close()

    typer.echo("")
    _print_summary(summaries, len(events), pii_hits, len(findings), redact)

    if not findings_only:
        _print_events(events, limit, show_all)
    _print_findings(findings, no_rules)

    if track_errors:
        typer.echo(f"\n  Errors tracked: {errors_tracked:,} -> {cfg.db_path}")


# ---------------------------------------------------------------------------
# fleet tail
# ---------------------------------------------------------------------------


def _event_visible(event: Event, show_events: bool, min_threshold: Optional[int]) -> bool:
    """Decide whether a raw event is printed (findings always print separately)."""
    if show_events:
        return True
    if min_threshold is None:
        return False
    return event.severity.level >= min_threshold


def _print_event(event: Event) -> None:
    ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "no timestamp"
    sev = event.severity.value.upper().ljust(8)
    tgt = str(event.parsed_fields.get("target", "?"))
    typer.echo(f"  {ts}  {sev}  {tgt}  {event.message[:100]}")


def _print_heartbeat(
    status: dict[str, str], events_window: int, hb_interval: float, total_findings: int
) -> None:
    up = sum(1 for s in status.values() if s == "up")
    down = [name for name, s in status.items() if s != "up"]
    line = (
        f"  [heartbeat {datetime.now().strftime('%H:%M:%S')}]  {up}/{len(status)} up  ·  "
        f"{events_window} ev/{hb_interval:g}s  ·  {total_findings} findings"
    )
    if down:
        line += f"  ·  down: {', '.join(down)}"
    typer.echo(typer.style(line, fg=typer.colors.BRIGHT_BLACK))


def _tail_worker(name: str, adapter: SourceAdapter, interval: float, q: queue.Queue) -> None:
    """Drain one target's poll() into the shared queue. Runs as a daemon thread."""

    async def _drain() -> None:
        async for event in adapter.poll(interval):  # type: ignore[attr-defined]
            event.parsed_fields["target"] = name
            q.put(("event", name, event))

    try:
        asyncio.run(_drain())
        q.put(("down", name, "stream ended"))
    except Exception as e:
        q.put(("down", name, str(e)))


@app.command("tail")
def fleet_tail(
    targets_file: Annotated[Path, typer.Option("--targets", help="Targets file to load.")] = Path(
        "targets.yaml"
    ),
    target: Annotated[
        Optional[list[str]],
        typer.Option("--target", help="Select a target by name (repeatable)."),
    ] = None,
    group: Annotated[
        Optional[list[str]],
        typer.Option("--group", help="Select targets by group (repeatable)."),
    ] = None,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between polls, per target.")
    ] = 10.0,
    heartbeat_interval: Annotated[
        float, typer.Option("--heartbeat-interval", help="Seconds between heartbeat lines.")
    ] = 30.0,
    no_heartbeat: Annotated[
        bool, typer.Option("--no-heartbeat", help="Suppress the heartbeat line.")
    ] = False,
    show_events: Annotated[
        bool, typer.Option("--show-events", help="Print every event, not just findings.")
    ] = False,
    min_severity: Annotated[
        Optional[str],
        typer.Option("--min-severity", help="Also print raw events at/above this severity."),
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
    """Follow every configured target in real time — redact PII, run rules, alert.

    Each target is polled in its own thread and the events are merged into
    one stream. By default only findings print, with a periodic heartbeat;
    a target that drops out is reported but the rest keep running. File
    targets cannot be followed and are skipped. Runs until Ctrl+C.
    """
    min_threshold: Optional[int] = None
    if min_severity is not None:
        try:
            min_threshold = Severity(min_severity.lower()).level
        except ValueError:
            raise typer.BadParameter(
                f"--min-severity must be one of: {', '.join(s.value for s in Severity)}"
            )

    try:
        selected = select_targets(load_targets(targets_file), target, group)
    except TargetConfigError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

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

    # Only targets whose adapter supports poll() can be followed.
    tailable: list[tuple[str, SourceAdapter]] = []
    notices: list[str] = []
    for t in selected:
        try:
            adapter = build_adapter(t)
        except Exception as e:
            notices.append(f"{t.name}: skipped — {e}")
            continue
        if hasattr(adapter, "poll"):
            tailable.append((t.name, adapter))
        else:
            notices.append(f"{t.name}: skipped — type '{t.type}' has no realtime tail")

    if not tailable:
        typer.echo("Error: no tailable targets (file targets cannot be followed).", err=True)
        raise typer.Exit(1)

    sep = "  " + "-" * 66
    if show_events:
        out_mode = "all events + findings"
    elif min_threshold is not None:
        out_mode = f"findings + events at/above {(min_severity or '').lower()}"
    else:
        out_mode = "findings only"
    typer.echo(f"\n{sep}")
    typer.echo(f"  Fleet tail — {len(tailable)} target(s)")
    typer.echo(f"  Poll      : every {poll_interval:g}s")
    if not no_heartbeat:
        typer.echo(f"  Heartbeat : every {heartbeat_interval:g}s")
    typer.echo(f"  Output    : {out_mode}")
    typer.echo(f"  Rules     : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook   : {alert_webhook}  (min: {alert_min_severity})")
    for note in notices:
        typer.echo(typer.style(f"  Note      : {note}", fg=typer.colors.YELLOW))
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    e_repo: ErrorsRepository | None = None
    f_repo: FindingsRepository | None = None
    d_repo: DismissRepository | None = None
    tracker: ErrorTracker | None = None
    if track_errors:
        e_repo = ErrorsRepository(cfg.db_path)
        e_repo.open()
        tracker = ErrorTracker(e_repo)
    if track_findings:
        f_repo = FindingsRepository(cfg.db_path)
        f_repo.open()
    if engine:
        d_repo = DismissRepository(cfg.db_path)
        d_repo.open()

    q: queue.Queue = queue.Queue()
    status = {name: "up" for name, _ in tailable}
    for name, adapter in tailable:
        threading.Thread(
            target=_tail_worker, args=(name, adapter, poll_interval, q), daemon=True
        ).start()

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}
    events_window = 0
    last_hb = time.monotonic()
    notifiers = build_notifiers(
        cfg.alerts, alert_webhook=alert_webhook, alert_min_severity=alert_min_severity
    )

    try:
        while True:
            try:
                kind, name, payload = q.get(timeout=1.0)
            except queue.Empty:
                kind = name = payload = None  # type: ignore[assignment]

            if kind == "event":
                event = payload
                result = redactor.redact(event.message)
                event.message = result.text
                event.raw = redactor.redact(event.raw).text
                counts["pii"] += len(result.hits)
                counts["events"] += 1
                events_window += 1

                if _event_visible(event, show_events, min_threshold):
                    _print_event(event)

                if engine:
                    for finding in engine.process(event):
                        if d_repo and d_repo.is_dismissed(finding.rule_id, finding.source):
                            continue
                        _print_finding(name, finding)
                        counts["findings"] += 1
                        counts["webhooks"] += dispatch(notifiers, finding)
                        if f_repo and meets_min_severity(finding, cfg.findings_min_severity):
                            f_repo.add_findings([finding])
                if tracker and tracker.process(event) is not None:
                    counts["errors"] += 1

            elif kind == "down":
                status[name] = "down"
                typer.echo(
                    typer.style(f"  [target down]  {name}: {payload}", fg=typer.colors.RED),
                    err=True,
                )
                if all(s != "up" for s in status.values()):
                    typer.echo("  All targets down — stopping.")
                    break

            if not no_heartbeat and time.monotonic() - last_hb >= heartbeat_interval:
                _print_heartbeat(status, events_window, heartbeat_interval, counts["findings"])
                events_window = 0
                last_hb = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        if e_repo:
            e_repo.close()
        if f_repo:
            f_repo.close()
        if d_repo:
            d_repo.close()

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


# ---------------------------------------------------------------------------
# fleet init
# ---------------------------------------------------------------------------


def _prompt_type() -> str:
    """Prompt for a target type, re-asking until a known type is given."""
    typer.echo("    Types: " + ", ".join(sorted(TYPE_FIELDS)))
    while True:
        choice = typer.prompt("    Type").strip().lower()
        if choice in TYPE_FIELDS:
            return choice
        typer.echo(typer.style(f"    unknown type '{choice}'", fg=typer.colors.RED))


def _prompt_field(field, env_vars: set[str]):
    """Prompt for one target field; returns the value to store, or None to omit."""
    if field.kind == "bool":
        return True if typer.confirm(f"    {field.label}", default=False) else None
    if field.kind == "secret":
        var = typer.prompt(
            f"    {field.label} — environment variable name (empty to skip)", default=""
        ).strip()
        if not var:
            return None
        env_vars.add(var)
        return f"${{{var}}}"
    value = typer.prompt(f"    {field.label}", default=field.default).strip()
    while field.required and not value:
        value = typer.prompt(f"    {field.label} (required)").strip()
    return value or None


@app.command("init")
def fleet_init(
    output: Annotated[Path, typer.Option("--output", "-o", help="Targets file to write.")] = Path(
        "targets.yaml"
    ),
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing targets file.")
    ] = False,
) -> None:
    """Interactively build a fleet targets file.

    Prompts for one target at a time — name, type, and that type's fields —
    and writes a targets.yaml. Credentials are stored as ${ENV_VAR}
    references, never as plain values.
    """
    if output.exists() and not force:
        typer.echo(f"Error: {output} already exists — use --force to overwrite.", err=True)
        raise typer.Exit(1)

    typer.echo("\n  Build a fleet targets file. Answer the prompts for each target.")

    entries: list[dict] = []
    env_vars: set[str] = set()
    names: set[str] = set()

    while True:
        typer.echo(f"\n  Target #{len(entries) + 1}")
        name = typer.prompt("    Target name").strip()
        while not name or name in names:
            reason = "a name is required" if not name else f"'{name}' is already used"
            typer.echo(typer.style(f"    {reason}", fg=typer.colors.RED))
            name = typer.prompt("    Target name").strip()
        names.add(name)

        ttype = _prompt_type()

        params: dict = {}
        for field in TYPE_FIELDS[ttype]:
            value = _prompt_field(field, env_vars)
            if value is not None:
                params[field.name] = value

        groups_raw = typer.prompt("    Groups — comma-separated (optional)", default="").strip()
        groups = [g.strip() for g in groups_raw.split(",") if g.strip()]

        entry: dict = {"name": name, "type": ttype}
        if groups:
            entry["groups"] = groups
        entry.update(params)
        entries.append(entry)

        if not typer.confirm("\n  Add another target?", default=False):
            break

    output.write_text(
        yaml.safe_dump({"targets": entries}, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    typer.echo(f"\n  Wrote {len(entries)} target(s) to {output}")
    if env_vars:
        typer.echo("  Set these environment variables before running fleet commands:")
        for var in sorted(env_vars):
            typer.echo(f"    export {var}=...")


# ---------------------------------------------------------------------------
# fleet list
# ---------------------------------------------------------------------------


def _endpoint_url(target: Target) -> str:
    p = target.params
    if target.type == "loki":
        return str(p.get("url", "http://localhost:3100"))
    if target.type == "graylog":
        return str(p.get("url", "http://localhost:9000"))
    scheme = "https" if p.get("use_ssl") else "http"  # opensearch
    return f"{scheme}://{p.get('host', 'localhost')}:{p.get('port', 9200)}"


def _http_reachable(url: str, timeout: float) -> tuple[bool, str]:
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True, ""
    except urllib.error.HTTPError:
        return True, ""  # the server answered (even an error) — it is reachable
    except Exception as e:
        return False, str(getattr(e, "reason", e))[:80]


def _probe(target: Target, timeout: float) -> tuple[bool, str]:
    """Quick reachability check for one target. Returns (reachable, detail)."""
    p = target.params
    try:
        if target.type == "file":
            ok = bool(p.get("path")) and Path(p["path"]).exists()
            return ok, "" if ok else "file not found"
        if target.type == "journald":
            ok = shutil.which("journalctl") is not None
            return ok, "" if ok else "journalctl not on PATH"
        if target.type == "ssh":
            result = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    f"ConnectTimeout={int(timeout)}",
                    str(p.get("host", "")),
                    "true",
                ],
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
            ok = result.returncode == 0
            return ok, "" if ok else result.stderr.strip()[:80]
        if target.type == "docker":
            from logatory.adapters.docker import _require_docker

            _require_docker().from_env().ping()
            return True, ""
        if target.type == "kubernetes":
            ok = shutil.which("kubectl") is not None
            return ok, "" if ok else "kubectl not on PATH"
        if target.type == "windows":
            if p.get("path"):
                ok = Path(p["path"]).exists()
                return ok, "" if ok else "file not found"
            ok = shutil.which("powershell") is not None or shutil.which("pwsh") is not None
            return ok, "" if ok else "powershell not on PATH"
        if target.type in ("s3", "cloudwatch"):
            ok = shutil.which("aws") is not None
            return ok, "" if ok else "aws CLI not on PATH"
        if target.type == "gcp":
            ok = shutil.which("gcloud") is not None
            return ok, "" if ok else "gcloud CLI not on PATH"
        if target.type in ("loki", "graylog", "opensearch"):
            return _http_reachable(_endpoint_url(target), timeout)
        return False, "unknown type"
    except Exception as e:
        return False, str(e)[:80]


@app.command("list")
def fleet_list(
    targets_file: Annotated[Path, typer.Option("--targets", help="Targets file to load.")] = Path(
        "targets.yaml"
    ),
    target: Annotated[
        Optional[list[str]],
        typer.Option("--target", help="Select a target by name (repeatable)."),
    ] = None,
    group: Annotated[
        Optional[list[str]],
        typer.Option("--group", help="Select targets by group (repeatable)."),
    ] = None,
    check: Annotated[
        bool, typer.Option("--check", help="Probe each target's reachability.")
    ] = False,
    timeout: Annotated[
        float, typer.Option("--timeout", help="Per-target probe timeout, seconds.")
    ] = 5.0,
) -> None:
    """List the configured fleet targets, optionally probing reachability."""
    try:
        selected = select_targets(load_targets(targets_file), target, group)
    except TargetConfigError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)

    statuses: list[tuple[bool, str]] = []
    if check:
        typer.echo(f"\n  Probing {len(selected)} target(s)...")
        with ThreadPoolExecutor(max_workers=max(1, min(16, len(selected)))) as pool:
            statuses = list(pool.map(lambda t: _probe(t, timeout), selected))

    name_w = max([len("NAME")] + [len(t.name) for t in selected])
    type_w = max([len("TYPE")] + [len(t.type) for t in selected])
    sep = "  " + "-" * 66
    typer.echo(f"\n{sep}")
    if check:
        typer.echo(
            f"  {'NAME'.ljust(name_w)}  {'TYPE'.ljust(type_w)}  {'STATUS'.ljust(12)}  GROUPS"
        )
    else:
        typer.echo(f"  {'NAME'.ljust(name_w)}  {'TYPE'.ljust(type_w)}  GROUPS")
    typer.echo(sep)

    for i, t in enumerate(selected):
        groups = ", ".join(t.groups) or "—"
        if check:
            ok, detail = statuses[i]
            label = "reachable" if ok else "unreachable"
            color = typer.colors.GREEN if ok else typer.colors.RED
            status = typer.style(label.ljust(12), fg=color)
            typer.echo(f"  {t.name.ljust(name_w)}  {t.type.ljust(type_w)}  {status}  {groups}")
            if not ok and detail:
                typer.echo(f"  {' ' * name_w}  └─ {detail}")
        else:
            typer.echo(f"  {t.name.ljust(name_w)}  {t.type.ljust(type_w)}  {groups}")

    typer.echo(sep)
    if check:
        up = sum(1 for ok, _ in statuses if ok)
        typer.echo(
            f"  {len(selected)} target(s) · {up} reachable · {len(selected) - up} unreachable"
        )
    else:
        typer.echo(f"  {len(selected)} target(s)")
    typer.echo(sep)
