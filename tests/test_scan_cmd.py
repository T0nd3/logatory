"""Tests for cli/main.py — the `scan` command and related helpers.

Strategy: invoke the Typer CLI via CliRunner with temporary log files.
No network, no LLM, no stdin — just file-based scanning.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from logatory.cli.main import _format_event, _format_finding, app
from logatory.models import Event, Finding, FindingSeverity, Severity

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg_file(tmp_path: Path, db_name: str = "test.db") -> tuple[Path, list[str]]:
    """Return (db_path, --config args) for a temp config."""
    db_path = tmp_path / db_name
    cfg = tmp_path / "logatory.yaml"
    cfg.write_text(f"db_path: {db_path}\n")
    return db_path, ["--config", str(cfg)]


def _write_log(tmp_path: Path, lines: list[str], name: str = "test.log") -> Path:
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Unit tests for pure helpers
# ---------------------------------------------------------------------------


class TestFormatEvent:
    def _event(self, msg: str = "hello", sev: Severity = Severity.INFO) -> Event:
        from datetime import UTC, datetime

        return Event(
            raw=msg,
            source="test.log",
            message=msg,
            severity=sev,
            timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC),
        )

    def test_contains_message(self) -> None:
        out = _format_event(self._event("disk full"), 1)
        assert "disk full" in out

    def test_contains_timestamp(self) -> None:
        out = _format_event(self._event(), 1)
        assert "2026-01-15" in out

    def test_contains_severity(self) -> None:
        out = _format_event(self._event(sev=Severity.ERROR), 1)
        assert "ERROR" in out

    def test_index_in_output(self) -> None:
        out = _format_event(self._event(), 42)
        assert "42" in out

    def test_long_message_truncated(self) -> None:
        long_msg = "x" * 200
        out = _format_event(self._event(long_msg), 1)
        assert len(out) < 300


class TestFormatFinding:
    def _finding(self) -> Finding:
        from datetime import UTC, datetime

        return Finding(
            rule_id="TEST_RULE",
            severity=FindingSeverity.HIGH,
            message="test alert",
            source="test.log",
            timestamp=datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC),
        )

    def test_contains_rule_id(self) -> None:
        assert "TEST_RULE" in _format_finding(self._finding())

    def test_contains_severity(self) -> None:
        assert "HIGH" in _format_finding(self._finding())

    def test_contains_message(self) -> None:
        assert "test alert" in _format_finding(self._finding())

    def test_contains_timestamp(self) -> None:
        assert "2026-01-15" in _format_finding(self._finding())


# ---------------------------------------------------------------------------
# scan — basic behaviour
# ---------------------------------------------------------------------------


class TestScanBasic:
    def test_file_not_found_exits_1(self, tmp_path: Path) -> None:
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(tmp_path / "missing.log")] + cfg)
        assert result.exit_code == 1

    def test_file_not_found_message(self, tmp_path: Path) -> None:
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(tmp_path / "missing.log")] + cfg)
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    def test_json_lines_file_parsed(self, tmp_path: Path) -> None:
        log = _write_log(
            tmp_path,
            [
                '{"level": "info", "message": "server started"}',
                '{"level": "warning", "message": "disk space low"}',
                '{"level": "error", "message": "connection refused"}',
            ],
        )
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log)] + cfg)
        assert result.exit_code == 0
        assert "3" in result.output  # 3 events parsed

    def test_shows_event_count(self, tmp_path: Path) -> None:
        log = _write_log(tmp_path, ['{"level": "info", "message": "ok"}'] * 5)
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log)] + cfg)
        assert result.exit_code == 0
        assert "5" in result.output

    def test_pii_redacted_in_output(self, tmp_path: Path) -> None:
        log = _write_log(
            tmp_path,
            ['{"level": "info", "message": "user john.doe@example.com logged in"}'],
        )
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log)] + cfg)
        assert result.exit_code == 0
        assert "john.doe@example.com" not in result.output

    def test_format_only_flag(self, tmp_path: Path) -> None:
        log = _write_log(tmp_path, ['{"level": "info", "message": "test"}'])
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--format-only"] + cfg)
        assert result.exit_code == 0
        # Should mention detected format
        assert "json" in result.output.lower() or "format" in result.output.lower()

    def test_no_rules_flag_skips_engine(self, tmp_path: Path) -> None:
        log = _write_log(
            tmp_path,
            ["Failed password for root from 10.0.0.1 port 22 ssh2"] * 20,
            "auth.log",
        )
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--no-rules"] + cfg)
        assert result.exit_code == 0
        # With --no-rules, findings count must be 0
        assert "Findings : 0" in result.output

    def test_empty_file_handled(self, tmp_path: Path) -> None:
        log = tmp_path / "empty.log"
        log.write_text("")
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log)] + cfg)
        assert result.exit_code == 0

    def test_gzip_file_parsed(self, tmp_path: Path) -> None:
        import gzip

        log_gz = tmp_path / "test.log.gz"
        with gzip.open(log_gz, "wt", encoding="utf-8") as f:
            f.write('{"level": "info", "message": "gzip ok"}\n')
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log_gz)] + cfg)
        assert result.exit_code == 0
        assert "1" in result.output


# ---------------------------------------------------------------------------
# scan — rule engine / findings
# ---------------------------------------------------------------------------


class TestScanRuleEngine:
    def test_ssh_brute_force_detected(self, tmp_path: Path) -> None:
        lines = [
            f"May 21 12:00:{i:02d} server sshd[1]: "
            f"Failed password for root from 10.0.0.1 port 22 ssh2"
            for i in range(15)
        ]
        log = _write_log(tmp_path, lines, "auth.log")
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log)] + cfg)
        assert result.exit_code == 0
        # At least one finding triggered
        assert "finding" in result.output.lower()

    def test_show_all_flag(self, tmp_path: Path) -> None:
        lines = [f'{{"level": "info", "message": "event {i}"}}' for i in range(60)]
        log = _write_log(tmp_path, lines)
        _, cfg = _cfg_file(tmp_path)
        result_default = runner.invoke(app, ["scan", str(log)] + cfg)
        result_all = runner.invoke(app, ["scan", str(log), "--all"] + cfg)
        assert result_all.exit_code == 0
        # --all shows more events (default limit is 50)
        assert len(result_all.output) >= len(result_default.output)

    def test_limit_flag(self, tmp_path: Path) -> None:
        lines = ['{"level": "info", "message": "event"}'] * 20
        log = _write_log(tmp_path, lines)
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--limit", "5"] + cfg)
        assert result.exit_code == 0
        assert result.exit_code == 0


class TestScanJson:
    def test_json_output_is_valid_and_machine_readable(self, tmp_path: Path) -> None:
        import json

        lines = [f'{{"level": "info", "message": "event {i}"}}' for i in range(5)]
        log = _write_log(tmp_path, lines)
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--json"] + cfg)
        assert result.exit_code == 0, result.output
        # stdout is a single JSON object — and not the human summary
        assert "Source   :" not in result.output
        data = json.loads(result.output)
        assert data["events"] == 5
        assert data["format"] == "json_lines"
        assert "findings" in data and isinstance(data["findings"], list)
        assert len(data["events_sample"]) == 5

    def test_json_includes_findings(self, tmp_path: Path) -> None:
        import json

        lines = [
            f"May 21 12:00:{i:02d} server sshd[1]: "
            f"Failed password for root from 10.0.0.1 port 22 ssh2"
            for i in range(15)
        ]
        log = _write_log(tmp_path, lines, "auth.log")
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--json"] + cfg)
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["findings_count"] >= 1
        f = data["findings"][0]
        assert {"rule_id", "severity", "message", "source"} <= set(f)

    def test_json_events_sample_respects_limit(self, tmp_path: Path) -> None:
        import json

        lines = ['{"level": "info", "message": "event"}'] * 20
        log = _write_log(tmp_path, lines)
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--json", "--limit", "5"] + cfg)
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["events"] == 20
        assert len(data["events_sample"]) == 5

    def test_json_track_errors_keys(self, tmp_path: Path) -> None:
        import json

        lines = ['{"level": "error", "message": "ConnectionError: refused"}'] * 3
        log = _write_log(tmp_path, lines)
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--json", "--track-errors"] + cfg)
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "errors_tracked" in data
        assert "findings_tracked" in data


# ---------------------------------------------------------------------------
# scan — error tracking
# ---------------------------------------------------------------------------


class TestScanTrackErrors:
    def test_track_errors_persists_to_db(self, tmp_path: Path) -> None:
        lines = [
            '{"level": "error", "message": "ConnectionError: refused"}',
            '{"level": "error", "message": "ConnectionError: refused"}',
        ]
        log = _write_log(tmp_path, lines)
        db_path, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--track-errors"] + cfg)
        assert result.exit_code == 0
        # DB should now exist and contain errors
        assert db_path.exists()

    def test_track_errors_shows_count(self, tmp_path: Path) -> None:
        lines = ['{"level": "error", "message": "Something failed"}'] * 3
        log = _write_log(tmp_path, lines)
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--track-errors"] + cfg)
        assert result.exit_code == 0
        assert "error" in result.output.lower()


# ---------------------------------------------------------------------------
# scan — PII redaction modes
# ---------------------------------------------------------------------------


class TestScanRedactModes:
    _LOG_LINE = '{"level": "info", "message": "user 192.168.1.42 connected"}'

    def test_redact_mode_default(self, tmp_path: Path) -> None:
        log = _write_log(tmp_path, [self._LOG_LINE])
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--redact", "redact"] + cfg)
        assert result.exit_code == 0
        assert "192.168.1.42" not in result.output

    def test_mask_mode(self, tmp_path: Path) -> None:
        log = _write_log(tmp_path, [self._LOG_LINE])
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--redact", "mask"] + cfg)
        assert result.exit_code == 0
        assert "192.168.1.42" not in result.output

    def test_dry_run_mode_reports_hits(self, tmp_path: Path) -> None:
        log = _write_log(tmp_path, [self._LOG_LINE])
        _, cfg = _cfg_file(tmp_path)
        result = runner.invoke(app, ["scan", str(log), "--redact", "dry-run"] + cfg)
        assert result.exit_code == 0
        # dry-run reports hits with the mode label but leaves the original
        # text unchanged — that is the whole point of the mode
        assert "dry-run" in result.output
        assert "PII hits" in result.output
        assert "192.168.1.42" in result.output


# ---------------------------------------------------------------------------
# rules validate / list
# ---------------------------------------------------------------------------


class TestRulesSubcommands:
    # rules list / validate have no --config option (they don't touch the DB)

    def test_rules_list_shows_builtin(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["rules", "list"])
        assert result.exit_code == 0
        # Should list at least the SSH brute-force rule
        assert "ssh" in result.output.lower() or "rule" in result.output.lower()

    def test_rules_list_shows_count(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["rules", "list"])
        assert result.exit_code == 0
        assert "rule(s) loaded" in result.output

    def test_rules_validate_valid_file(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(
            "id: TEST_RULE\n"
            "title: Test Rule\n"
            "level: high\n"
            "conditions:\n"
            "  - field: message\n"
            "    op: contains\n"
            "    value: error\n"
        )
        result = runner.invoke(app, ["rules", "validate", str(rule_file)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower() or "ok" in result.output.lower()

    def test_rules_validate_invalid_file(self, tmp_path: Path) -> None:
        rule_file = tmp_path / "bad_rule.yml"
        rule_file.write_text("not_a_valid: rule\n")
        result = runner.invoke(app, ["rules", "validate", str(rule_file)])
        # Should exit with error or show a validation failure message
        assert result.exit_code != 0 or "invalid" in result.output.lower()

    def test_rules_validate_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["rules", "validate", str(tmp_path / "no_such.yml")])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# export markdown
# ---------------------------------------------------------------------------


class TestExportMarkdown:
    """Integration test: generate_report returns valid Markdown."""

    def _seed(self, db_path: Path) -> None:
        from datetime import UTC, datetime

        from logatory.models import Finding, FindingSeverity
        from logatory.storage.errors_repo import ErrorsRepository
        from logatory.storage.findings_repo import FindingsRepository

        now = datetime.now(tz=UTC)
        findings = [
            Finding(
                rule_id="SSH_BRUTE",
                severity=FindingSeverity.CRITICAL,
                message="SSH brute force",
                source="auth.log",
                timestamp=now,
            ),
            Finding(
                rule_id="SQL_INJ",
                severity=FindingSeverity.HIGH,
                message="SQL injection",
                source="web.log",
                timestamp=now,
            ),
        ]
        with FindingsRepository(db_path) as repo:
            repo.add_findings(findings)

        with ErrorsRepository(db_path) as repo:
            repo.upsert(
                fingerprint="fp1",
                error_type="TimeoutError",
                normalized_msg="Timed out",
                severity="medium",
                source="app.log",
                timestamp=now,
                sample="Timed out after 30s",
            )

    def test_generate_report_returns_string(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report

        db = tmp_path / "test.db"
        self._seed(db)
        report = generate_report(db)
        assert isinstance(report, str)
        assert len(report) > 100

    def test_report_has_header(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report

        db = tmp_path / "test.db"
        self._seed(db)
        report = generate_report(db)
        assert "# Logatory Security Report" in report

    def test_report_has_summary_section(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report

        db = tmp_path / "test.db"
        self._seed(db)
        report = generate_report(db)
        assert "## Summary" in report

    def test_report_contains_rule_ids(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report

        db = tmp_path / "test.db"
        self._seed(db)
        report = generate_report(db)
        assert "SSH_BRUTE" in report

    def test_report_contains_error_types(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report

        db = tmp_path / "test.db"
        self._seed(db)
        report = generate_report(db)
        assert "TimeoutError" in report

    def test_report_custom_title(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report

        db = tmp_path / "test.db"
        self._seed(db)
        report = generate_report(db, title="My Custom Report")
        assert "My Custom Report" in report

    def test_report_empty_db(self, tmp_path: Path) -> None:
        from logatory.export.markdown import generate_report
        from logatory.storage.findings_repo import FindingsRepository

        db = tmp_path / "empty.db"
        with FindingsRepository(db):
            pass
        report = generate_report(db)
        assert "## Summary" in report
        assert "0" in report

    def test_md_table_helper(self) -> None:
        from logatory.export.markdown import _md_table

        table = _md_table(["A", "B"], [["x", "y"], ["1", "2"]])
        assert "| A | B |" in table
        assert "| x | y |" in table
        assert "---" in table

    def test_escape_pipe_characters(self) -> None:
        from logatory.export.markdown import _escape

        assert "\\|" in _escape("a|b")

    def test_escape_truncates_long_text(self) -> None:
        from logatory.export.markdown import _escape

        result = _escape("x" * 200, max_len=80)
        assert len(result) <= 82  # 80 + "…"
        assert "…" in result
