"""Tests for the GCP Cloud Logging source adapter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from logatory.adapters.gcp_logging import GCPLoggingAdapter, _parse_ts, _rfc3339
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _entry(
    *,
    text: str | None = None,
    json_payload: dict | None = None,
    proto_payload: dict | None = None,
    severity: str | None = None,
    timestamp: str | None = None,
    insert_id: str | None = None,
    log_name: str | None = None,
    resource_type: str | None = None,
) -> dict:
    entry: dict = {}
    if text is not None:
        entry["textPayload"] = text
    if json_payload is not None:
        entry["jsonPayload"] = json_payload
    if proto_payload is not None:
        entry["protoPayload"] = proto_payload
    if severity is not None:
        entry["severity"] = severity
    if timestamp is not None:
        entry["timestamp"] = timestamp
    if insert_id is not None:
        entry["insertId"] = insert_id
    if log_name is not None:
        entry["logName"] = log_name
    if resource_type is not None:
        entry["resource"] = {"type": resource_type}
    return entry


def _payload(*entries: dict) -> str:
    # gcloud emits newest-first.
    return json.dumps(list(entries))


class _Runner:
    """Injectable gcloud stand-in: returns queued payloads, records argv."""

    def __init__(self, *responses: str) -> None:
        self._responses = list(responses)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        return self._responses.pop(0) if self._responses else "[]"


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_rfc3339_z(self):
        dt = _parse_ts("2024-01-02T03:04:05Z")
        assert dt == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)

    def test_nanoseconds_truncated(self):
        dt = _parse_ts("2024-01-02T03:04:05.123456789Z")
        assert dt is not None
        assert dt.microsecond == 123456

    def test_offset_preserved(self):
        dt = _parse_ts("2024-01-02T03:04:05+02:00")
        assert dt is not None
        assert dt.utcoffset().total_seconds() == 7200

    def test_invalid(self):
        assert _parse_ts("nope") is None
        assert _parse_ts(None) is None
        assert _parse_ts("") is None

    def test_rfc3339_roundtrip(self):
        dt = datetime(2024, 1, 2, 3, 4, 5, 123000, tzinfo=UTC)
        rendered = _rfc3339(dt)
        assert rendered == "2024-01-02T03:04:05.123Z"


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------


class TestReadArgs:
    def test_filters_combined(self):
        adapter = GCPLoggingAdapter(log_filter="severity>=ERROR", project="proj-1", limit=500)
        args = adapter._read_args(extra_filter='timestamp > "x"', use_freshness=False)
        assert "logging" in args and "read" in args
        # combined filter is the single positional after "read"
        combined = args[3]
        assert combined == '(severity>=ERROR) AND (timestamp > "x")'
        assert "--format" in args and "json" in args
        assert "--limit" in args and "500" in args
        assert "--project" in args and "proj-1" in args
        assert "--freshness" not in args

    def test_freshness_added(self):
        adapter = GCPLoggingAdapter(since="2h")
        args = adapter._read_args(extra_filter=None, use_freshness=True)
        assert "--freshness" in args and "2h" in args

    def test_no_filter_no_positional(self):
        adapter = GCPLoggingAdapter()
        args = adapter._read_args(extra_filter=None, use_freshness=False)
        # right after "read" comes "--format"
        assert args[:4] == ["gcloud", "logging", "read", "--format"]


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_text_payload_oldest_first(self):
        runner = _Runner(
            _payload(
                _entry(text="second", timestamp="2024-01-01T00:00:02Z", insert_id="i2"),
                _entry(text="first", timestamp="2024-01-01T00:00:01Z", insert_id="i1"),
            )
        )
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["first", "second"]

    async def test_severity_mapped(self):
        runner = _Runner(_payload(_entry(text="boom", severity="ALERT")))
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].severity == Severity.CRITICAL
        assert events[0].parsed_fields["gcp_severity"] == "ALERT"

    async def test_json_payload_message(self):
        runner = _Runner(_payload(_entry(json_payload={"msg": "hi there", "k": 1})))
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].message == "hi there"

    async def test_json_payload_falls_back_to_dump(self):
        runner = _Runner(_payload(_entry(json_payload={"k": "v"})))
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert json.loads(events[0].message) == {"k": "v"}

    async def test_proto_payload(self):
        runner = _Runner(_payload(_entry(proto_payload={"methodName": "x"})))
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert json.loads(events[0].message) == {"methodName": "x"}

    async def test_fields_and_source(self):
        runner = _Runner(
            _payload(
                _entry(
                    text="hi",
                    log_name="projects/p/logs/stdout",
                    insert_id="abc",
                    resource_type="gce_instance",
                    timestamp="2024-01-01T00:00:01Z",
                )
            )
        )
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        ev = events[0]
        assert ev.source == "gce_instance"
        assert ev.parsed_fields["log_name"] == "projects/p/logs/stdout"
        assert ev.parsed_fields["insert_id"] == "abc"
        assert ev.parsed_fields["resource_type"] == "gce_instance"
        assert ev.timestamp == datetime(2024, 1, 1, 0, 0, 1, tzinfo=UTC)

    async def test_source_falls_back_to_log_name(self):
        runner = _Runner(_payload(_entry(text="hi", log_name="projects/p/logs/stderr")))
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].source == "stderr"

    async def test_entry_without_message_skipped(self):
        runner = _Runner(_payload(_entry(severity="INFO"), _entry(text="kept")))
        adapter = GCPLoggingAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["kept"]

    async def test_empty_returns_nothing(self):
        runner = _Runner("[]")
        adapter = GCPLoggingAdapter(runner=runner)
        assert [e async for e in adapter.events()] == []

    async def test_invalid_json_returns_nothing(self):
        runner = _Runner("not json")
        adapter = GCPLoggingAdapter(runner=runner)
        assert [e async for e in adapter.events()] == []


# ---------------------------------------------------------------------------
# Poll / dedup
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_dedup_by_insert_id(self):
        # Round 1: i1, i2. Round 2: re-returns i2 (inclusive boundary) + i3.
        runner = _Runner(
            _payload(
                _entry(text="r2", timestamp="2024-01-01T00:00:02Z", insert_id="i2"),
                _entry(text="r1", timestamp="2024-01-01T00:00:01Z", insert_id="i1"),
            ),
            _payload(
                _entry(text="r3", timestamp="2024-01-01T00:00:03Z", insert_id="i3"),
                _entry(text="r2", timestamp="2024-01-01T00:00:02Z", insert_id="i2"),
            ),
        )
        adapter = GCPLoggingAdapter(runner=runner)
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break
        assert collected == ["r1", "r2", "r3"]

    async def test_second_round_uses_timestamp_filter(self):
        runner = _Runner(
            _payload(_entry(text="r1", timestamp="2024-01-01T00:00:01Z", insert_id="i1")),
            _payload(_entry(text="r2", timestamp="2024-01-01T00:00:02Z", insert_id="i2")),
        )
        adapter = GCPLoggingAdapter(runner=runner)
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 2:
                break
        # first call: freshness, no timestamp clause
        first_args = runner.calls[0]
        assert "--freshness" in first_args
        # second call: timestamp filter present, freshness gone
        second_args = runner.calls[1]
        assert any("timestamp >" in a for a in second_args)
        assert "--freshness" not in second_args
