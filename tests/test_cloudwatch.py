"""Tests for the AWS CloudWatch Logs source adapter."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from logatory.adapters.cloudwatch import CloudWatchAdapter, _parse_lookback
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(message: str, *, ts_ms: int, stream: str = "stream-a", event_id: str = "e1") -> dict:
    return {
        "timestamp": ts_ms,
        "message": message,
        "logStreamName": stream,
        "eventId": event_id,
        "ingestionTime": ts_ms,
    }


def _payload(*events: dict) -> str:
    return json.dumps({"events": list(events)})


class _Runner:
    """Injectable aws stand-in: returns queued payloads, records argv."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        return self._responses.pop(0) if self._responses else _payload()


# ---------------------------------------------------------------------------
# Lookback parsing
# ---------------------------------------------------------------------------


class TestParseLookback:
    def test_units(self):
        assert _parse_lookback("30s") == 30
        assert _parse_lookback("5m") == 300
        assert _parse_lookback("1h") == 3600
        assert _parse_lookback("2d") == 172800

    def test_invalid(self):
        assert _parse_lookback("nope") is None
        assert _parse_lookback(None) is None
        assert _parse_lookback("") is None


# ---------------------------------------------------------------------------
# Construction / command building
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_log_group_required(self):
        with pytest.raises(ValueError, match="log_group"):
            CloudWatchAdapter(log_group="")

    def test_filter_args_include_options(self):
        adapter = CloudWatchAdapter(
            log_group="/app/prod",
            log_stream="s1",
            filter_pattern="ERROR",
            region="eu-central-1",
        )
        args = adapter._filter_args(start_ms=1000)
        assert "filter-log-events" in args
        assert "--log-group-name" in args and "/app/prod" in args
        assert "--log-stream-names" in args and "s1" in args
        assert "--filter-pattern" in args and "ERROR" in args
        assert "--start-time" in args and "1000" in args
        assert "--region" in args and "eu-central-1" in args

    def test_since_becomes_start_time(self):
        adapter = CloudWatchAdapter(log_group="g", since="1h")
        start = adapter._start_ms_from_since()
        assert start is not None
        expected = (datetime.now(tz=UTC) - timedelta(hours=1)).timestamp() * 1000
        assert abs(start - expected) < 5000  # within 5s


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_reads_and_tags_events(self):
        runner = _Runner(
            _payload(
                _event("hello one", ts_ms=1_700_000_000_000, event_id="e1"),
                _event("hello two", ts_ms=1_700_000_001_000, event_id="e2"),
            )
        )
        adapter = CloudWatchAdapter(log_group="/app/prod", runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["hello one", "hello two"]
        assert events[0].source == "/app/prod:stream-a"
        assert events[0].parsed_fields["log_group"] == "/app/prod"
        assert events[0].parsed_fields["log_stream"] == "stream-a"
        assert events[0].parsed_fields["event_id"] == "e1"
        assert events[0].timestamp is not None

    async def test_json_message_severity_extracted(self):
        body = json.dumps({"level": "error", "message": "boom"})
        runner = _Runner(_payload(_event(body, ts_ms=1_700_000_000_000)))
        adapter = CloudWatchAdapter(log_group="g", runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].severity == Severity.ERROR
        assert events[0].message == "boom"

    async def test_empty_returns_nothing(self):
        runner = _Runner(_payload())
        adapter = CloudWatchAdapter(log_group="g", runner=runner)
        assert [e async for e in adapter.events()] == []


# ---------------------------------------------------------------------------
# Poll / dedup
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_dedup_by_event_id(self):
        # Round 1: e1, e2. Round 2: re-returns e2 (inclusive boundary) + e3.
        runner = _Runner(
            _payload(
                _event("r1", ts_ms=1_700_000_000_000, event_id="e1"),
                _event("r2", ts_ms=1_700_000_001_000, event_id="e2"),
            ),
            _payload(
                _event("r2", ts_ms=1_700_000_001_000, event_id="e2"),
                _event("r3", ts_ms=1_700_000_002_000, event_id="e3"),
            ),
        )
        adapter = CloudWatchAdapter(log_group="g", runner=runner)
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break
        assert collected == ["r1", "r2", "r3"]
