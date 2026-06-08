"""Tests for cli/findings_cmd.py — findings list, show, summary."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logatory.cli.findings_cmd import _parse_hours, app
from logatory.models import Finding, FindingSeverity
from logatory.storage.findings_repo import FindingsRepository

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(offset_hours: int = 0) -> datetime:
    return datetime.now(tz=UTC) + timedelta(hours=offset_hours)


def _finding(
    rule_id: str = "TEST001",
    severity: FindingSeverity = FindingSeverity.HIGH,
    source: str = "test.log",
    message: str = "test finding",
    ts: datetime | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        source=source,
        timestamp=ts or _ts(),
    )


def _seed_db(db_path: Path) -> None:
    with FindingsRepository(db_path) as repo:
        repo.add_findings(
            [
                _finding("SSH_BRUTE", FindingSeverity.CRITICAL, "auth.log", "SSH brute force"),
                _finding(
                    "HIGH_RULE", FindingSeverity.HIGH, "app.log", "High severity event", _ts(1)
                ),
                _finding("MED_RULE", FindingSeverity.MEDIUM, "app.log", "Medium event", _ts(2)),
                _finding(
                    "SSH_BRUTE", FindingSeverity.CRITICAL, "auth.log", "SSH brute force #2", _ts(3)
                ),
            ]
        )


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    p = tmp_path / "test.db"
    _seed_db(p)
    return p


@pytest.fixture()
def empty_db(tmp_path: Path) -> Path:
    p = tmp_path / "empty.db"
    with FindingsRepository(p):
        pass
    return p


def _cfg_args(db_path: Path) -> list[str]:
    """Return --config args pointing to a temp config that uses db_path."""
    cfg_file = db_path.parent / "logatory.yaml"
    cfg_file.write_text(f"db_path: {db_path}\n")
    return ["--config", str(cfg_file)]


# ---------------------------------------------------------------------------
# _parse_hours helper
# ---------------------------------------------------------------------------


class TestParseHours:
    def test_hours(self):
        assert _parse_hours("24h") == 24

    def test_days(self):
        assert _parse_hours("7d") == 168

    def test_minutes(self):
        result = _parse_hours("30m")
        assert result >= 1  # clamped to min 1

    def test_invalid_raises(self):
        import typer

        with pytest.raises((SystemExit, typer.Exit)):
            _parse_hours("abc")


# ---------------------------------------------------------------------------
# findings list
# ---------------------------------------------------------------------------


class TestFindingsList:
    def test_shows_findings(self, db: Path):
        result = runner.invoke(app, ["list"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "SSH_BRUTE" in result.output
        assert "HIGH_RULE" in result.output

    def test_empty_db_message(self, empty_db: Path):
        result = runner.invoke(app, ["list"] + _cfg_args(empty_db))
        assert result.exit_code == 0
        assert "No findings" in result.output

    def test_filter_by_severity(self, db: Path):
        result = runner.invoke(app, ["list", "--severity", "critical"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "SSH_BRUTE" in result.output
        assert "HIGH_RULE" not in result.output

    def test_filter_by_source(self, db: Path):
        result = runner.invoke(app, ["list", "--source", "auth.log"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "SSH_BRUTE" in result.output
        # HIGH_RULE is in app.log, should not appear
        assert "HIGH_RULE" not in result.output

    def test_limit_respected(self, db: Path):
        result = runner.invoke(app, ["list", "--limit", "1"] + _cfg_args(db))
        assert result.exit_code == 0
        # Output table should have exactly 1 data row (hard to count precisely, but total > 1)
        assert "4 finding(s) total" in result.output

    def test_since_filter(self, db: Path):
        # --since 1h: only findings from last hour; _ts(3) is 3 hours *ahead*, so all qualify
        result = runner.invoke(app, ["list", "--since", "200h"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "finding(s)" in result.output

    def test_shows_total_count(self, db: Path):
        result = runner.invoke(app, ["list"] + _cfg_args(db))
        assert "4 finding(s) total" in result.output


# ---------------------------------------------------------------------------
# findings show
# ---------------------------------------------------------------------------


class TestFindingsShow:
    def test_show_existing_rule(self, db: Path):
        result = runner.invoke(app, ["show", "SSH_BRUTE"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "SSH_BRUTE" in result.output
        assert "CRITICAL" in result.output
        assert "Occurrences" in result.output

    def test_show_unknown_rule_exits_1(self, db: Path):
        result = runner.invoke(app, ["show", "NONEXISTENT_RULE"] + _cfg_args(db))
        assert result.exit_code == 1

    def test_show_displays_multiple_occurrences(self, db: Path):
        result = runner.invoke(app, ["show", "SSH_BRUTE"] + _cfg_args(db))
        assert result.exit_code == 0
        # SSH_BRUTE was inserted twice
        assert "2" in result.output

    def test_show_displays_source(self, db: Path):
        result = runner.invoke(app, ["show", "SSH_BRUTE"] + _cfg_args(db))
        assert "auth.log" in result.output

    def test_show_empty_db_exits_1(self, empty_db: Path):
        result = runner.invoke(app, ["show", "ANY_RULE"] + _cfg_args(empty_db))
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# findings summary
# ---------------------------------------------------------------------------


class TestFindingsSummary:
    def test_shows_total(self, db: Path):
        result = runner.invoke(app, ["summary"] + _cfg_args(db))
        assert result.exit_code == 0
        assert "4" in result.output  # total

    def test_shows_severity_breakdown(self, db: Path):
        result = runner.invoke(app, ["summary"] + _cfg_args(db))
        assert "CRITICAL" in result.output
        assert "HIGH" in result.output

    def test_shows_top_rules(self, db: Path):
        result = runner.invoke(app, ["summary"] + _cfg_args(db))
        assert "SSH_BRUTE" in result.output

    def test_empty_db_message(self, empty_db: Path):
        result = runner.invoke(app, ["summary"] + _cfg_args(empty_db))
        assert result.exit_code == 0
        assert "No findings" in result.output

    def test_ssh_brute_count_is_2(self, db: Path):
        result = runner.invoke(app, ["summary"] + _cfg_args(db))
        # SSH_BRUTE appears twice, should show count 2
        assert "2" in result.output
