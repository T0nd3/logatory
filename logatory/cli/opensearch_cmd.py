from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.adapters.opensearch import OpenSearchAdapter
from logatory.adapters.opensearch_config import (
    FieldMapping,
    OpenSearchAuth,
    OpenSearchQuery,
    TimeRange,
)
from logatory.cli._pipeline import run_tail_pipeline
from logatory.cli._scan import ScanResult, collect_scan, print_finding, render_scan
from logatory.config import Config
from logatory.pii.redactor import PIIRedactor, RedactMode
from logatory.rules import BUILTIN_RULES_DIR
from logatory.rules.engine import RuleEngine
from logatory.rules.loader import load_rules_dir

app = typer.Typer(help="Query logs from an OpenSearch / Elasticsearch cluster.")


def _build_engine(no_rules: bool, rules_dir: Optional[Path]) -> RuleEngine | None:
    if no_rules:
        return None
    all_rules = list(load_rules_dir(BUILTIN_RULES_DIR))
    if rules_dir and rules_dir.is_dir():
        all_rules.extend(load_rules_dir(rules_dir))
    return RuleEngine(all_rules)


def _parse_filters(filter_: Optional[list[str]]) -> list[dict[str, str]]:
    filters: list[dict[str, str]] = []
    for f in filter_ or []:
        if "=" not in f:
            typer.echo(
                f"Warning: ignoring malformed filter '{f}' (expected field=value)", err=True
            )
            continue
        k, _, v = f.partition("=")
        filters.append({"field": k.strip(), "value": v.strip()})
    return filters


@app.command("scan")
def opensearch_scan(
    # Connection
    host: Annotated[str, typer.Option("--host", "-H", help="OpenSearch host.")] = "localhost",
    port: Annotated[int, typer.Option("--port", "-p")] = 9200,
    use_ssl: Annotated[bool, typer.Option("--ssl/--no-ssl")] = False,
    no_verify: Annotated[
        bool, typer.Option("--no-verify-certs", help="Skip TLS cert verification.")
    ] = False,
    # Auth (all optional; env vars preferred over CLI flags)
    username: Annotated[
        Optional[str], typer.Option("--user", "-u", envvar="OPENSEARCH_USERNAME")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("--password", envvar="OPENSEARCH_PASSWORD")
    ] = None,
    api_key: Annotated[
        Optional[str], typer.Option("--api-key", envvar="OPENSEARCH_API_KEY")
    ] = None,
    # Query
    index: Annotated[str, typer.Option("--index", "-i", help="Index pattern.")] = "logstash-*",
    since: Annotated[
        Optional[str], typer.Option("--since", help="Start time: '24h', '7d', or ISO datetime.")
    ] = None,
    until: Annotated[
        Optional[str], typer.Option("--until", help="End time: 'now' or ISO datetime.")
    ] = None,
    filter_: Annotated[
        Optional[list[str]], typer.Option("--filter", "-f", help="field=value filter. Repeatable.")
    ] = None,
    max_events: Annotated[
        Optional[int], typer.Option("--max", help="Max events to fetch.")
    ] = None,
    page_size: Annotated[int, typer.Option("--page-size")] = 1000,
    # Field mapping overrides
    ts_field: Annotated[str, typer.Option("--ts-field")] = "@timestamp",
    msg_field: Annotated[str, typer.Option("--msg-field")] = "message",
    sev_field: Annotated[Optional[str], typer.Option("--sev-field")] = "level",
    src_field: Annotated[Optional[str], typer.Option("--src-field")] = "host.name",
    # Output
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n")] = 50,
    show_all: Annotated[bool, typer.Option("--all")] = False,
    no_rules: Annotated[bool, typer.Option("--no-rules")] = False,
    rules_dir: Annotated[Optional[Path], typer.Option("--rules-dir")] = None,
) -> None:
    """Fetch events from OpenSearch, redact PII, and run detection rules."""
    cfg = Config.load(config)

    # Merge CLI host/port with config-file defaults (CLI wins)
    os_cfg = cfg.opensearch
    effective_host = host if host != "localhost" else os_cfg.host
    effective_port = port if port != 9200 else os_cfg.port

    auth = OpenSearchAuth(
        username=username or os_cfg.username,
        password=password or os_cfg.password,
        api_key=api_key or os_cfg.api_key,
    )
    has_auth = any([auth.username, auth.api_key])

    query = OpenSearchQuery(
        index=index,
        time_range=TimeRange(since=since, until=until),
        filters=_parse_filters(filter_),
        field_mapping=FieldMapping(
            timestamp=ts_field,
            message=msg_field,
            severity=sev_field or None,
            source_name=src_field or None,
        ),
        page_size=page_size,
        max_events=max_events,
    )

    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt, rules_path=cfg.pii_rules_path, mode=RedactMode.REDACT
    )
    engine = _build_engine(no_rules, rules_dir)

    async def _run() -> ScanResult:
        adapter = OpenSearchAdapter(
            host=effective_host,
            port=effective_port,
            query=query,
            auth=auth if has_auth else None,
            use_ssl=use_ssl,
            verify_certs=not no_verify,
        )
        return await collect_scan(adapter.events(), redactor, engine)

    try:
        result = asyncio.run(_run())
    except Exception as e:
        typer.echo(f"Error connecting to OpenSearch: {e}", err=True)
        raise typer.Exit(1)

    render_scan(
        result,
        source_label=f"{effective_host}:{effective_port}/{index}",
        redact_mode="redact",
        limit=limit,
        show_all=show_all,
        no_rules=no_rules,
        cfg=cfg,
        show_source=False,
        msg_width=120,
    )


@app.command("tail")
def opensearch_tail(
    host: Annotated[str, typer.Option("--host", "-H", help="OpenSearch host.")] = "localhost",
    port: Annotated[int, typer.Option("--port", "-p")] = 9200,
    use_ssl: Annotated[bool, typer.Option("--ssl/--no-ssl")] = False,
    no_verify: Annotated[
        bool, typer.Option("--no-verify-certs", help="Skip TLS cert verification.")
    ] = False,
    username: Annotated[
        Optional[str], typer.Option("--user", "-u", envvar="OPENSEARCH_USERNAME")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("--password", envvar="OPENSEARCH_PASSWORD")
    ] = None,
    api_key: Annotated[
        Optional[str], typer.Option("--api-key", envvar="OPENSEARCH_API_KEY")
    ] = None,
    index: Annotated[str, typer.Option("--index", "-i", help="Index pattern.")] = "logstash-*",
    since: Annotated[
        str, typer.Option("--since", help="Initial lookback window: '5m', '1h'.")
    ] = "5m",
    filter_: Annotated[
        Optional[list[str]], typer.Option("--filter", "-f", help="field=value filter. Repeatable.")
    ] = None,
    poll_interval: Annotated[
        float, typer.Option("--poll-interval", help="Seconds between OpenSearch queries.")
    ] = 15.0,
    ts_field: Annotated[str, typer.Option("--ts-field")] = "@timestamp",
    msg_field: Annotated[str, typer.Option("--msg-field")] = "message",
    sev_field: Annotated[Optional[str], typer.Option("--sev-field")] = "level",
    src_field: Annotated[Optional[str], typer.Option("--src-field")] = "host.name",
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    no_rules: Annotated[bool, typer.Option("--no-rules")] = False,
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
    """Poll an OpenSearch index in real time — redact PII, run rules, alert.

    Queries the index every --poll-interval seconds for newly-arrived
    events and processes them through the same pipeline as `tail`.
    Runs until Ctrl+C.
    """
    cfg = Config.load(config)
    os_cfg = cfg.opensearch
    effective_host = host if host != "localhost" else os_cfg.host
    effective_port = port if port != 9200 else os_cfg.port

    auth = OpenSearchAuth(
        username=username or os_cfg.username,
        password=password or os_cfg.password,
        api_key=api_key or os_cfg.api_key,
    )
    has_auth = any([auth.username, auth.api_key])

    query = OpenSearchQuery(
        index=index,
        time_range=TimeRange(since=since),
        filters=_parse_filters(filter_),
        field_mapping=FieldMapping(
            timestamp=ts_field,
            message=msg_field,
            severity=sev_field or None,
            source_name=src_field or None,
        ),
    )

    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt, rules_path=cfg.pii_rules_path, mode=RedactMode.REDACT
    )
    engine = _build_engine(no_rules, rules_dir)

    sep = "-" * 60
    typer.echo(f"\n{sep}")
    typer.echo(f"  Polling  : {effective_host}:{effective_port}/{index}")
    typer.echo(f"  Interval : {poll_interval}s   Lookback: {since}")
    typer.echo(f"  Rules    : {'off' if no_rules else 'on'}")
    if alert_webhook:
        typer.echo(f"  Webhook  : {alert_webhook}  (min: {alert_min_severity})")
    typer.echo("  Press Ctrl+C to stop.")
    typer.echo(f"{sep}\n")

    counts = {"events": 0, "findings": 0, "pii": 0, "errors": 0, "webhooks": 0}

    async def _run() -> None:
        adapter = OpenSearchAdapter(
            host=effective_host,
            port=effective_port,
            query=query,
            auth=auth if has_auth else None,
            use_ssl=use_ssl,
            verify_certs=not no_verify,
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
        typer.echo(f"\nError: {e}", err=True)
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


@app.command("info")
def opensearch_info(
    host: Annotated[str, typer.Option("--host", "-H")] = "localhost",
    port: Annotated[int, typer.Option("--port", "-p")] = 9200,
    use_ssl: Annotated[bool, typer.Option("--ssl/--no-ssl")] = False,
    no_verify: Annotated[bool, typer.Option("--no-verify-certs")] = False,
    username: Annotated[
        Optional[str], typer.Option("--user", envvar="OPENSEARCH_USERNAME")
    ] = None,
    password: Annotated[
        Optional[str], typer.Option("--password", envvar="OPENSEARCH_PASSWORD")
    ] = None,
    api_key: Annotated[
        Optional[str], typer.Option("--api-key", envvar="OPENSEARCH_API_KEY")
    ] = None,
) -> None:
    """Check cluster connectivity and print basic cluster info."""
    try:
        from logatory.adapters.opensearch import _make_client
        from logatory.adapters.opensearch_config import OpenSearchAuth
    except ImportError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)

    auth = OpenSearchAuth(username=username, password=password, api_key=api_key)
    has_auth = any([auth.username, auth.api_key])

    try:
        client = _make_client(host, port, use_ssl, not no_verify, auth if has_auth else None)
        info = client.info()
        name = info.get("cluster_name", "?")
        version = info.get("version", {}).get("number", "?")
        typer.echo(
            typer.style(f"Connected  cluster={name}  version={version}", fg=typer.colors.GREEN)
        )
    except Exception as e:
        typer.echo(typer.style(f"Connection failed: {e}", fg=typer.colors.RED), err=True)
        raise typer.Exit(1)
