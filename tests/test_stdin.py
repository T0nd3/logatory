"""Tests for the stdin source adapter."""

from __future__ import annotations

import io
import json

import pytest

from logatory.adapters.stdin import StdinAdapter
from logatory.models import Severity
from logatory.parsers.detector import LogFormat


@pytest.fixture
def feed_stdin(monkeypatch):
    """Replace sys.stdin with an in-memory stream of the given text."""

    def _feed(text: str) -> None:
        monkeypatch.setattr("sys.stdin", io.StringIO(text))

    return _feed


async def _collect(adapter: StdinAdapter) -> list:
    return [e async for e in adapter.events()]


# ---------------------------------------------------------------------------
# Basic reading
# ---------------------------------------------------------------------------


class TestStdinAdapter:
    async def test_reads_plaintext_lines(self, feed_stdin):
        feed_stdin("first line\nsecond line\nthird line\n")
        events = await _collect(StdinAdapter())
        assert [e.message for e in events] == ["first line", "second line", "third line"]

    async def test_source_is_stdin(self, feed_stdin):
        feed_stdin("something happened\n")
        events = await _collect(StdinAdapter())
        assert events[0].source == "stdin"

    async def test_empty_input_yields_nothing(self, feed_stdin):
        feed_stdin("")
        assert await _collect(StdinAdapter()) == []

    async def test_blank_lines_skipped(self, feed_stdin):
        feed_stdin("\n\nreal line\n\n")
        events = await _collect(StdinAdapter())
        assert len(events) == 1
        assert events[0].message == "real line"

    async def test_line_without_trailing_newline(self, feed_stdin):
        feed_stdin("no newline at end")
        events = await _collect(StdinAdapter())
        assert len(events) == 1
        assert events[0].message == "no newline at end"


# ---------------------------------------------------------------------------
# Format detection driven by the sample
# ---------------------------------------------------------------------------


class TestStdinFormatDetection:
    async def test_json_lines_detected_and_parsed(self, feed_stdin):
        line = json.dumps({"level": "ERROR", "message": "connection refused"})
        feed_stdin((line + "\n") * 3)
        events = await _collect(StdinAdapter())
        assert len(events) == 3
        assert events[0].severity == Severity.ERROR
        assert events[0].message == "connection refused"

    async def test_logfmt_detected(self, feed_stdin):
        feed_stdin(
            "level=info msg=started port=8080\n"
            "level=warn msg=cache_miss key=a\n"
            "level=error msg=db_down attempt=3\n"
        )
        events = await _collect(StdinAdapter())
        assert len(events) == 3
        assert events[2].severity == Severity.ERROR
        assert events[0].parsed_fields["port"] == "8080"

    async def test_cef_detected(self, feed_stdin):
        feed_stdin(
            "CEF:0|V|FW|1.0|100|blocked|8|src=10.0.0.1 dst=8.8.8.8\n"
            "CEF:0|V|FW|1.0|101|allowed|2|src=10.0.0.2 dst=1.1.1.1\n"
        )
        events = await _collect(StdinAdapter())
        assert len(events) == 2
        assert events[0].severity == Severity.ERROR
        assert events[0].parsed_fields["src"] == "10.0.0.1"

    async def test_sample_uses_first_nonblank_lines(self, feed_stdin):
        # Leading blank lines must not derail JSON detection.
        line = json.dumps({"level": "INFO", "msg": "hi"})
        feed_stdin("\n\n" + (line + "\n") * 3)
        events = await _collect(StdinAdapter())
        assert len(events) == 3
        assert all(e.message == "hi" for e in events)

    def test_plaintext_fallback_for_prose(self, feed_stdin):
        # Sanity check: arbitrary prose detects as plaintext (no crash, 1 event).
        from logatory.parsers.detector import FormatDetector

        assert FormatDetector().detect(["just some words here"]) == LogFormat.PLAINTEXT
