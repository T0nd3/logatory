from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.file import FileAdapter
from logatory.adapters.stdin import StdinAdapter
from logatory.anomaly.baseline import compute_stats
from logatory.anomaly.detector import (
    anomaly_results_to_findings,
)
from logatory.anomaly.detector import (
    detect_anomalies as run_anomaly_detection,
)
from logatory.anomaly.features import FeatureExtractor
from logatory.cli import serve_cmd, tail_cmd
from logatory.cli._types import REDACT_MAP, RedactModeArg
from logatory.cli.anomaly_cmd import app as anomaly_app
from logatory.cli.colors import SEVERITY_COLOR
from logatory.cli.demo_cmd import app as demo_app
from logatory.cli.docker_cmd import app as docker_app
from logatory.cli.errors_cmd import app as errors_app
from logatory.cli.export_cmd import app as export_app
from logatory.cli.findings_cmd import app as findings_app
from logatory.cli.fleet_cmd import app as fleet_app
from logatory.cli.graylog_cmd import app as graylog_app
from logatory.cli.journald_cmd import app as journald_app
from logatory.cli.kubernetes_cmd import app as kubernetes_app
from logatory.cli.llm_cmd import app as llm_app
from logatory.cli.loki_cmd import app as loki_app
from logatory.cli.opensearch_cmd import app as opensearch_app
from logatory.cli.ssh_cmd import app as ssh_app
from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.models import Event, Finding
from logatory.parsers.detector import FormatDetector
from logatory.pii.patterns import PIIPattern
from logatory.pii.redactor import PIIRedactor
from logatory.plugins.loader import compile_plugin_pii_patterns, load_plugins
from logatory.rules import BUILTIN_RULES_DIR
from logatory.rules.loader import build_engine, load_rules_dir, validate_rule_file
from logatory.rules.sigma import SigmaConversionError, load_sigma_file
from logatory.storage.baseline_repo import BaselineRepository
from logatory.storage.dismiss_repo import DismissRepository
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository, meets_min_severity

app = typer.Typer(name="logatory", help="Logatory — local log analysis with LLM support.")
app.command("tail")(tail_cmd.tail_watch)
app.command("serve")(serve_cmd.serve)
rules_app = typer.Typer(help="Manage detection rules.")
app.add_typer(rules_app, name="rules")
app.add_typer(opensearch_app, name="opensearch")
app.add_typer(docker_app, name="docker")
app.add_typer(journald_app, name="journald")
app.add_typer(kubernetes_app, name="kubernetes")
app.add_typer(ssh_app, name="ssh")
app.add_typer(loki_app, name="loki")
app.add_typer(graylog_app, name="graylog")
app.add_typer(fleet_app, name="fleet")
app.add_typer(errors_app, name="errors")
app.add_typer(findings_app, name="findings")
app.add_typer(anomaly_app, name="anomaly")
app.add_typer(llm_app, name="llm")
app.add_typer(demo_app, name="demo")
app.add_typer(export_app, name="export")


def _load_config(config_path: Path | None) -> Config:
    return Config.load(config_path)


def _make_redactor(
    cfg: Config,
    mode,
    plugin_pii: list[PIIPattern] | None = None,
) -> PIIRedactor:
    return PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
        mode=mode,
        additional=plugin_pii,
    )


def _format_event(event: Event, index: int) -> str:
    ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S") if event.timestamp else "no timestamp"
    sev = event.severity.value.upper().ljust(8)
    return f"  [{index:>5}] {ts}  {sev}  {event.message[:120]}"


def _format_finding(finding: Finding) -> str:
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    sev = finding.severity.value.upper()
    return f"  [{sev}] {ts}  {finding.rule_id}  {finding.message}"


def _detect_format_name(adapter) -> str:
    if isinstance(adapter, StdinAdapter):
        return "auto-detected"
    if isinstance(adapter, FileAdapter):
        lines: list[str] = []
        try:
            for line in adapter._read_lines():
                if line.strip():
                    lines.append(line)
                if len(lines) >= 5:
                    break
            return FormatDetector().detect(lines, adapter.path).value
        except Exception:
            return "unknown"
    return "unknown"


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    path: Annotated[
        Optional[Path], typer.Argument(help="Log file to scan. Use '-' for stdin.")
    ] = None,
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    redact: Annotated[RedactModeArg, typer.Option("--redact")] = RedactModeArg.redact,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max events to display.")] = 50,
    show_all: Annotated[bool, typer.Option("--all")] = False,
    format_only: Annotated[bool, typer.Option("--format-only")] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules", help="Skip rule engine.")] = False,
    rules_dir: Annotated[
        Optional[Path], typer.Option("--rules-dir", help="Extra rules directory.")
    ] = None,
    track_errors: Annotated[
        bool, typer.Option("--track-errors", help="Persist errors to SQLite DB.")
    ] = False,
    detect_anomalies: Annotated[
        bool,
        typer.Option(
            "--detect-anomalies", help="Run statistical anomaly detection against baseline."
        ),
    ] = False,
    anomaly_source: Annotated[
        Optional[str],
        typer.Option("--anomaly-source", help="Baseline source key (default: file stem)."),
    ] = None,
    anomaly_threshold: Annotated[
        float, typer.Option("--anomaly-threshold", help="Z-score threshold for anomaly alerts.")
    ] = 3.0,
    explain_findings: Annotated[
        bool,
        typer.Option(
            "--explain-findings", help="Ask LLM to explain HIGH/CRITICAL findings after scan."
        ),
    ] = False,
    classify: Annotated[
        bool,
        typer.Option("--classify", help="Ask LLM to classify a sample of events by severity."),
    ] = False,
) -> None:
    """Parse a log file, redact PII, run detection rules, and optionally track errors."""
    cfg = _load_config(config)
    use_stdin = path is None or str(path) == "-"

    # Load plugins first so their PII patterns are available to the redactor
    plugin_registry = load_plugins(cfg.plugins_dir)
    plugin_pii = compile_plugin_pii_patterns(plugin_registry)
    redactor = _make_redactor(cfg, REDACT_MAP[redact], plugin_pii=plugin_pii or None)

    # Load rules (built-in + CLI --rules-dir + plugins)
    engine = build_engine(no_rules, rules_dir, plugin_registry)

    # These lists are populated inside _run() and read afterwards
    events: list[Event] = []
    findings: list[Finding] = []
    pii_hits_total_ref: list[int] = [0]
    errors_tracked_ref: list[int] = [0]
    adapter_ref: list = [None]

    async def _run() -> None:
        if use_stdin:
            adapter = StdinAdapter()
            typer.echo("Reading from stdin...", err=True)
        else:
            if not path or not path.exists():
                typer.echo(f"Error: file not found: {path}", err=True)
                raise typer.Exit(1)
            adapter = FileAdapter(path)
        adapter_ref[0] = adapter

        repo: ErrorsRepository | None = None
        tracker: ErrorTracker | None = None
        if track_errors:
            repo = ErrorsRepository(cfg.db_path)
            repo.open()
            tracker = ErrorTracker(repo)

        try:
            async for event in adapter.events():
                result = redactor.redact(event.message)
                event.message = result.text
                event.raw = redactor.redact(event.raw).text
                pii_hits_total_ref[0] += len(result.hits)
                events.append(event)
                if engine:
                    findings.extend(engine.process(event))
                if tracker and tracker.process(event) is not None:
                    errors_tracked_ref[0] += 1
        finally:
            if repo:
                repo.close()

    asyncio.run(_run())

    adapter = adapter_ref[0]
    pii_hits_total = pii_hits_total_ref[0]
    errors_tracked = errors_tracked_ref[0]

    # ------------------------------------------------------------------
    # Anomaly detection (post-processing, synchronous)
    # ------------------------------------------------------------------
    anomaly_mode_msg = ""
    if detect_anomalies and events:
        source_key = anomaly_source or (path.stem if path else "stdin")
        extractor = FeatureExtractor(bucket_seconds=60)
        buckets = extractor.extract(events)

        if buckets:
            with BaselineRepository(cfg.db_path) as bl_repo:
                baseline = bl_repo.get_stats(source_key)
                feature_dicts = [b.to_feature_dict() for b in buckets]
                bucket_timestamps = [b.ts for b in buckets]

                # Always add new observations to grow the baseline over time
                bl_repo.add_observations(source_key, feature_dicts, bucket_timestamps)
                all_fds = bl_repo.get_all_feature_dicts(source_key)
                stats = compute_stats(all_fds, source_key)
                bl_repo.update_stats(stats)

            if baseline and baseline.is_trained():
                anomaly_results = run_anomaly_detection(
                    buckets,
                    baseline,
                    threshold=anomaly_threshold,
                    baseline_feature_dicts=all_fds,
                )
                anomaly_findings = anomaly_results_to_findings(anomaly_results, source_key)
                findings.extend(anomaly_findings)
                anomaly_mode_msg = (
                    f"  Anomaly  : {len(anomaly_findings)} finding(s) (source: {source_key})\n"
                )
            else:
                n_obs = len(all_fds)
                anomaly_mode_msg = (
                    f"  Anomaly  : observe mode ({n_obs}/5 buckets for '{source_key}')"
                    " -- run more scans to train baseline\n"
                )

    # ------------------------------------------------------------------
    # Dismiss filter — remove suppressed findings before display/persist
    # ------------------------------------------------------------------
    if findings:
        with DismissRepository(cfg.db_path) as d_repo:
            findings = [f for f in findings if not d_repo.is_dismissed(f.rule_id, f.source)]

    # ------------------------------------------------------------------
    # Finding persistence (Option B) — only when --track-errors is active
    # ------------------------------------------------------------------
    findings_tracked = 0
    if track_errors and findings:
        eligible = [f for f in findings if meets_min_severity(f, cfg.findings_min_severity)]
        if eligible:
            with FindingsRepository(cfg.db_path) as f_repo:
                f_repo.cleanup_old(cfg.findings_retention_days)
                findings_tracked = f_repo.add_findings(eligible)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    fmt_name = _detect_format_name(adapter) if adapter else "unknown"
    sep = "-" * 60
    typer.echo(
        f"\n{sep}\n"
        f"  Source   : {path or 'stdin'}\n"
        f"  Format   : {fmt_name}\n"
        f"  Events   : {len(events):,}\n"
        f"  PII hits : {pii_hits_total:,} (mode: {redact.value})\n"
        f"  Findings : {len(findings):,}"
        + (
            f"  ({findings_tracked} new ≥{cfg.findings_min_severity} saved)"
            if track_errors
            else ""
        )
        + "\n"
        + (f"  Errors   : {errors_tracked:,} tracked to {cfg.db_path}\n" if track_errors else "")
        + anomaly_mode_msg
        + f"{sep}"
    )

    if format_only:
        return

    # Events section
    sample = events if show_all else events[:limit]
    if sample:
        typer.echo(f"\n  Events ({len(sample)} of {len(events):,}):\n")
        for i, ev in enumerate(sample, 1):
            typer.echo(_format_event(ev, i))
        if not show_all and len(events) > limit:
            typer.echo(f"\n  ... {len(events) - limit:,} more. Use --all or --limit N.")

    # Findings section
    if findings:
        typer.echo(f"\n  Findings ({len(findings)}):\n")
        for finding in findings:
            color = SEVERITY_COLOR.get(finding.severity.value, typer.colors.WHITE)
            typer.echo(typer.style(_format_finding(finding), fg=color))
    elif not no_rules:
        typer.echo("\n  No findings.")

    # ------------------------------------------------------------------
    # LLM explanations for high/critical findings (optional)
    # ------------------------------------------------------------------
    if explain_findings and findings:
        from logatory.llm.factory import make_llm_client
        from logatory.llm.prompts import explain_finding_prompt

        priority = [f for f in findings if f.severity.value in ("high", "critical")][
            :3
        ]  # cap at 3 to stay within reasonable time

        if not priority:
            typer.echo("\n  --explain-findings: no high/critical findings to explain.")
        else:
            llm_client = make_llm_client(cfg.llm)
            if llm_client.is_cloud:
                typer.echo(
                    "\n  [!] Cloud provider — redacted log data will be sent externally.",
                    err=True,
                )
            if not llm_client.is_available():
                typer.echo(
                    f"\n  --explain-findings: LLM provider '{cfg.llm.provider}' not reachable.",
                    err=True,
                )
            else:
                typer.echo(
                    f"\n  LLM explanations ({len(priority)} finding(s), model: {cfg.llm.model}):\n"
                )
                for finding in priority:
                    typer.echo(f"\n  >> {finding.rule_id} [{finding.severity.value.upper()}]")
                    typer.echo("-" * 55)
                    prompt = explain_finding_prompt(finding)
                    try:
                        for token in llm_client.generate(prompt, stream=True):
                            print(token, end="", flush=True)
                        print()
                    except Exception as e:
                        typer.echo(f"\n  LLM error: {e}", err=True)
                        break
                    typer.echo("-" * 55)

    # ------------------------------------------------------------------
    # LLM classification of event sample (optional)
    # ------------------------------------------------------------------
    if classify and events:
        from logatory.llm.factory import make_llm_client
        from logatory.llm.prompts import classify_events_prompt

        llm_client = make_llm_client(cfg.llm)
        if llm_client.is_cloud:
            typer.echo(
                "\n  [!] Cloud provider — redacted log data will be sent externally.",
                err=True,
            )
        if not llm_client.is_available():
            typer.echo(
                f"\n  --classify: LLM provider '{cfg.llm.provider}' not reachable.",
                err=True,
            )
        else:
            # Sample: prefer events without a clear non-INFO severity for more useful output
            sample_events = [e for e in events if e.severity.value in ("info", "debug")][:30]
            if not sample_events:
                sample_events = events[:30]

            log_lines = [e.message for e in sample_events]
            prompt = classify_events_prompt(log_lines)

            typer.echo(
                f"\n  LLM classification ({len(log_lines)} event sample, model: {cfg.llm.model}):\n"
            )
            typer.echo("-" * 55)
            try:
                for token in llm_client.generate(prompt, stream=True):
                    print(token, end="", flush=True)
                print()
            except Exception as e:
                typer.echo(f"\n  LLM error: {e}", err=True)
            typer.echo("-" * 55)


# ---------------------------------------------------------------------------
# rules list
# ---------------------------------------------------------------------------


@rules_app.command("list")
def rules_list(
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
) -> None:
    """List all loaded detection rules."""
    all_rules = list(load_rules_dir(BUILTIN_RULES_DIR))
    if rules_dir and rules_dir.is_dir():
        all_rules.extend(load_rules_dir(rules_dir))

    if not all_rules:
        typer.echo("No rules found.")
        return

    typer.echo(f"\n  {'ID':<30} {'LEVEL':<10} {'TITLE'}")
    typer.echo(f"  {'-' * 30} {'-' * 10} {'-' * 35}")
    for rule in sorted(all_rules, key=lambda r: r.id):
        color = SEVERITY_COLOR.get(rule.level.value, typer.colors.WHITE)
        level_str = typer.style(rule.level.value.upper().ljust(10), fg=color)
        typer.echo(f"  {rule.id:<30} {level_str} {rule.title}")
    typer.echo(f"\n  {len(all_rules)} rule(s) loaded.")


# ---------------------------------------------------------------------------
# rules validate
# ---------------------------------------------------------------------------


@rules_app.command("validate")
def rules_validate(
    file: Annotated[Path, typer.Argument(help="Rule file to validate (.yml).")],
    sigma: Annotated[bool, typer.Option("--sigma", help="Treat as Sigma format.")] = False,
) -> None:
    """Validate a rule file (own format or Sigma)."""
    if not file.exists():
        typer.echo(f"Error: file not found: {file}", err=True)
        raise typer.Exit(1)

    if sigma:
        try:
            rule = load_sigma_file(file)
            typer.echo(typer.style(f"OK  [{rule.id}] {rule.title}", fg=typer.colors.GREEN))
        except SigmaConversionError as e:
            typer.echo(typer.style(f"FAIL  {e}", fg=typer.colors.RED), err=True)
            raise typer.Exit(1)
    else:
        errors = validate_rule_file(file)
        if errors:
            for err in errors:
                typer.echo(typer.style(f"  ERROR  {err}", fg=typer.colors.RED))
            raise typer.Exit(1)
        else:
            import yaml

            with open(file) as f:
                data = yaml.safe_load(f)
            typer.echo(
                typer.style(
                    f"OK  [{data.get('id', '?')}] {data.get('title', '?')}",
                    fg=typer.colors.GREEN,
                )
            )


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print version."""
    from logatory import __version__

    typer.echo(f"logatory {__version__}")


if __name__ == "__main__":
    app()
