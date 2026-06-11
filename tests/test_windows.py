"""Tests for the Windows Event Log source adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logatory.adapters.windows import (
    WindowsEventLogAdapter,
    _map_event,
    _parse_payload,
    _parse_ts,
)
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(
    message: str = "The service entered the running state.",
    *,
    event_id: int = 7036,
    level: int | None = 4,
    level_name: str | None = "Information",
    provider: str = "Service Control Manager",
    log_name: str = "System",
    record_id: int = 1000,
    time_created: str = "/Date(1747908000000)/",
) -> dict:
    obj = {
        "TimeCreated": time_created,
        "Id": event_id,
        "ProviderName": provider,
        "LogName": log_name,
        "Message": message,
        "MachineName": "WIN-HOST",
        "RecordId": record_id,
    }
    if level is not None:
        obj["Level"] = level
    if level_name is not None:
        obj["LevelDisplayName"] = level_name
    return obj


class _Runner:
    """Injectable PowerShell stand-in: returns canned JSON, records calls."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        return self._responses.pop(0) if self._responses else ""


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_dotnet_date(self):
        dt = _parse_ts("/Date(1747908000000)/")
        assert dt is not None and dt.year == 2025

    def test_dotnet_date_with_offset(self):
        dt = _parse_ts("/Date(1747908000000+0200)/")
        assert dt is not None and dt.year == 2025

    def test_iso8601(self):
        dt = _parse_ts("2026-05-18T10:00:00Z")
        assert dt is not None and dt.year == 2026

    def test_epoch_milliseconds(self):
        dt = _parse_ts(1747908000000)
        assert dt is not None and dt.year == 2025

    def test_invalid_returns_none(self):
        assert _parse_ts("not-a-date") is None
        assert _parse_ts(None) is None


# ---------------------------------------------------------------------------
# Event mapping
# ---------------------------------------------------------------------------


class TestMapEvent:
    def test_basic_fields(self):
        ev = _map_event(_event(message="hello", provider="MyProvider"))
        assert ev is not None
        assert ev.message == "hello"
        assert ev.source == "MyProvider"
        assert ev.timestamp is not None
        assert ev.parsed_fields["event_id"] == 7036
        assert ev.parsed_fields["record_id"] == 1000

    def test_numeric_level_to_severity(self):
        cases = {1: Severity.CRITICAL, 2: Severity.ERROR, 3: Severity.WARNING, 5: Severity.DEBUG}
        for level, expected in cases.items():
            ev = _map_event(_event(level=level, level_name=None))
            assert ev is not None and ev.severity == expected, f"level {level}"

    def test_level_name_fallback(self):
        ev = _map_event(_event(level=None, level_name="Error"))
        assert ev is not None and ev.severity == Severity.ERROR

    def test_missing_message_synthesized(self):
        ev = _map_event({"Id": 4625, "ProviderName": "Security-Auditing"})
        assert ev is not None
        assert "4625" in ev.message
        assert "Security-Auditing" in ev.message

    def test_no_message_no_id_returns_none(self):
        assert _map_event({"ProviderName": "x"}) is None

    def test_source_falls_back_to_log_name(self):
        ev = _map_event({"Id": 1, "Message": "x", "LogName": "Application"})
        assert ev is not None and ev.source == "Application"


# ---------------------------------------------------------------------------
# Payload parsing
# ---------------------------------------------------------------------------


class TestParsePayload:
    def test_single_object(self):
        objs = _parse_payload(json.dumps(_event()))
        assert len(objs) == 1

    def test_array(self):
        objs = _parse_payload(json.dumps([_event(), _event(record_id=1001)]))
        assert len(objs) == 2

    def test_json_lines_fallback(self):
        text = "\n".join(json.dumps(_event(record_id=r)) for r in (1, 2, 3))
        # Not a single valid JSON doc, but valid JSON Lines.
        objs = _parse_payload(text)
        assert len(objs) == 3

    def test_empty_returns_empty(self):
        assert _parse_payload("") == []
        assert _parse_payload("   ") == []


# ---------------------------------------------------------------------------
# File mode (batch)
# ---------------------------------------------------------------------------


class TestEventsFromFile:
    async def test_reads_array_export(self, tmp_path: Path):
        export = tmp_path / "system.json"
        export.write_text(
            json.dumps([_event(message="one", record_id=1), _event(message="two", record_id=2)])
        )
        adapter = WindowsEventLogAdapter(path=export)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["one", "two"]

    async def test_reads_bom_prefixed_file(self, tmp_path: Path):
        export = tmp_path / "bom.json"
        export.write_bytes(b"\xef\xbb\xbf" + json.dumps(_event(message="withbom")).encode("utf-8"))
        adapter = WindowsEventLogAdapter(path=export)
        events = [e async for e in adapter.events()]
        assert events[0].message == "withbom"

    async def test_missing_file_raises(self, tmp_path: Path):
        adapter = WindowsEventLogAdapter(path=tmp_path / "nope.json")
        with pytest.raises(RuntimeError, match="not found"):
            _ = [e async for e in adapter.events()]


# ---------------------------------------------------------------------------
# Live mode (PowerShell runner)
# ---------------------------------------------------------------------------


class TestEventsLive:
    async def test_live_fetch_via_runner(self):
        runner = _Runner(json.dumps([_event(message="live one"), _event(message="live two")]))
        adapter = WindowsEventLogAdapter(log="System", runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["live one", "live two"]
        # The generated PowerShell command targets the requested log.
        assert any("Get-WinEvent" in part for part in runner.calls[0])
        assert any("LogName='System'" in part for part in runner.calls[0])

    async def test_provider_filter_in_script(self):
        runner = _Runner(json.dumps(_event()))
        adapter = WindowsEventLogAdapter(log="System", provider="Foo", runner=runner)
        _ = [e async for e in adapter.events()]
        assert any("ProviderName='Foo'" in part for part in runner.calls[0])

    def test_needs_path_or_log(self):
        with pytest.raises(ValueError, match=r"path.*or.*log"):
            WindowsEventLogAdapter()


# ---------------------------------------------------------------------------
# Polling / dedup
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_dedup_by_record_id(self):
        # Round 1 returns records 1,2; round 2 re-returns 2 and adds 3.
        runner = _Runner(
            json.dumps([_event(message="r2", record_id=2), _event(message="r1", record_id=1)]),
            json.dumps([_event(message="r3", record_id=3), _event(message="r2", record_id=2)]),
        )
        adapter = WindowsEventLogAdapter(log="System", runner=runner)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break

        # Newest-first batches are reversed to oldest-first; r2 not repeated.
        assert collected == ["r1", "r2", "r3"]
