"""Tests for the shared scan helpers in cli/_scan.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from logatory.cli._scan import (
    ScanResult,
    build_pipeline,
    collect_scan,
    print_finding,
    render_scan,
)
from logatory.cli._types import RedactModeArg
from logatory.config import Config
from logatory.models import Event, Finding, FindingSeverity, Severity


def _event(msg: str, src: str = "src") -> Event:
    return Event(raw=msg, source=src, message=msg, severity=Severity.INFO, timestamp=None)


# ---------------------------------------------------------------------------
# build_pipeline
# ---------------------------------------------------------------------------


def test_build_pipeline_builds_engine(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("db_path: x.db\n")
    cfg, redactor, engine = build_pipeline(cfg_file, RedactModeArg.redact, False, None)
    assert cfg.db_path == Path("x.db")
    assert redactor is not None
    assert engine is not None  # built-in rules loaded


def test_build_pipeline_no_rules_disables_engine(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("db_path: x.db\n")
    _, _, engine = build_pipeline(cfg_file, RedactModeArg.redact, True, None)
    assert engine is None


# ---------------------------------------------------------------------------
# collect_scan
# ---------------------------------------------------------------------------


async def test_collect_scan_redacts_and_collects():
    from logatory.pii.redactor import PIIRedactor

    redactor = PIIRedactor.from_config(salt="s", rules_path=Path("__no_such_file__"))

    async def _stream():
        for i in range(2):
            yield _event(f"user a@b.com did event {i}")

    result = await collect_scan(_stream(), redactor, None)
    assert len(result.events) == 2
    assert result.pii_hits >= 2  # one email per event redacted
    assert "a@b.com" not in result.events[0].message


# ---------------------------------------------------------------------------
# render_scan / print_finding
# ---------------------------------------------------------------------------


def test_render_scan_basic(capsys):
    finding = Finding(
        rule_id="R1",
        severity=FindingSeverity.HIGH,
        message="bad thing",
        source="src",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    result = ScanResult(events=[_event("hello world")], findings=[finding], pii_hits=3)
    render_scan(
        result,
        source_label="MySource (1 unit(s))",
        redact_mode="redact",
        limit=50,
        show_all=False,
        no_rules=False,
        cfg=Config(),
    )
    out = capsys.readouterr().out
    assert "Source     : MySource (1 unit(s))" in out
    assert "Events     : 1" in out
    assert "PII hits   : 3 (mode: redact)" in out
    assert "Findings   : 1" in out
    assert "hello world" in out
    assert "R1" in out and "bad thing" in out


def test_render_scan_extra_lines_and_no_findings(capsys):
    result = ScanResult(events=[_event("e")], findings=[], pii_hits=0)
    render_scan(
        result,
        source_label="Docker (2 container(s))",
        redact_mode="redact",
        limit=50,
        show_all=False,
        no_rules=False,
        cfg=Config(),
        extra_lines=["  Containers : a, b"],
    )
    out = capsys.readouterr().out
    assert "Containers : a, b" in out
    assert "No findings." in out


def test_render_scan_hides_source_field(capsys):
    result = ScanResult(events=[_event("payload", src="ignored")], findings=[], pii_hits=0)
    render_scan(
        result,
        source_label="ES",
        redact_mode="redact",
        limit=50,
        show_all=False,
        no_rules=True,
        cfg=Config(),
        show_source=False,
        msg_width=120,
    )
    out = capsys.readouterr().out
    assert "payload" in out
    assert "ignored" not in out  # source column suppressed


def test_print_tail_header(capsys):
    from logatory.cli._pipeline import print_tail_header

    print_tail_header(
        ["  Following : X"], no_rules=False, alert_webhook="http://h", alert_min_severity="high"
    )
    out = capsys.readouterr().out
    assert "Following : X" in out
    assert "Rules     : on" in out
    assert "Webhook   : http://h" in out
    assert "Press Ctrl+C to stop." in out


def test_print_tail_summary(capsys):
    from logatory.cli._pipeline import print_tail_summary

    print_tail_summary(
        {"events": 5, "pii": 2, "findings": 1, "errors": 3, "webhooks": 4},
        track_errors=True,
        alert_webhook="http://h",
    )
    out = capsys.readouterr().out
    assert "Stopped." in out
    assert "Events   : 5" in out
    assert "Errors   : 3 tracked" in out
    assert "Webhooks : 4 sent" in out


def test_print_tail_summary_minimal(capsys):
    from logatory.cli._pipeline import print_tail_summary

    print_tail_summary({"events": 0, "pii": 0, "findings": 0, "errors": 0, "webhooks": 0})
    out = capsys.readouterr().out
    assert "Errors" not in out  # not shown unless track_errors
    assert "Webhooks" not in out  # not shown unless alert_webhook


def test_print_finding(capsys):
    finding = Finding(
        rule_id="RULE_X",
        severity=FindingSeverity.CRITICAL,
        message="boom",
        source="s",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
    )
    print_finding(finding)
    out = capsys.readouterr().out
    assert "RULE_X" in out and "boom" in out and "CRITICAL" in out
