"""Tests for TailAdapter and tail_helpers."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from logatory.adapters.tail import TailAdapter
from logatory.models import Finding, FindingSeverity
from logatory.tail_helpers import meets_alert_severity, post_webhook

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _collect(adapter: TailAdapter, n: int, timeout: float = 3.0) -> list:
    """Collect up to *n* events from an adapter, stopping after *timeout* s."""
    events: list = []

    async def _inner() -> None:
        async for event in adapter.events():
            events.append(event)
            if len(events) >= n:
                return

    try:
        await asyncio.wait_for(_inner(), timeout=timeout)
    except TimeoutError:
        pass
    return events


def _finding(sev: FindingSeverity = FindingSeverity.HIGH) -> Finding:
    return Finding(
        rule_id="TEST",
        severity=sev,
        message="test",
        source="test.log",
        timestamp=datetime.now(tz=UTC),
    )


def _write(path: Path, text: str, append: bool = False) -> None:
    mode = "a" if append else "w"
    with open(path, mode, encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# TailAdapter — from_start
# ---------------------------------------------------------------------------


class TestTailAdapterFromStart:
    def test_reads_existing_lines(self, tmp_path: Path):
        log = tmp_path / "app.log"
        _write(log, "plain error message\nanother line\n")

        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)
        events = asyncio.run(_collect(adapter, 2))
        assert len(events) == 2

    def test_single_line(self, tmp_path: Path):
        log = tmp_path / "app.log"
        _write(log, "error: disk full\n")

        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)
        events = asyncio.run(_collect(adapter, 1))
        assert len(events) == 1

    def test_json_lines_parsed(self, tmp_path: Path):
        log = tmp_path / "app.log"
        line = json.dumps({"level": "ERROR", "msg": "connection refused"}) + "\n"
        _write(log, line * 3)

        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)
        events = asyncio.run(_collect(adapter, 3))
        assert len(events) == 3
        assert "connection refused" in events[0].message

    def test_empty_lines_skipped(self, tmp_path: Path):
        log = tmp_path / "app.log"
        _write(log, "\n\nerror: oops\n\n")

        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)
        events = asyncio.run(_collect(adapter, 1))
        assert len(events) == 1

    def test_source_set_to_file_path(self, tmp_path: Path):
        log = tmp_path / "myapp.log"
        _write(log, "something happened\n")

        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)
        events = asyncio.run(_collect(adapter, 1))
        assert str(log) in events[0].source


# ---------------------------------------------------------------------------
# TailAdapter — tail mode (seek to end, pick up new lines)
# ---------------------------------------------------------------------------


class TestTailAdapterTailMode:
    def test_picks_up_new_lines_after_start(self, tmp_path: Path):
        log = tmp_path / "app.log"
        _write(log, "old line\n")  # existing content — should be skipped

        adapter = TailAdapter(log, from_start=False, poll_interval=0.05)

        async def _run():
            events = []

            async def _append_after_delay():
                await asyncio.sleep(0.15)
                _write(log, "new error occurred\n", append=True)

            task = asyncio.create_task(_append_after_delay())
            async for ev in adapter.events():
                events.append(ev)
                break
            task.cancel()
            return events

        events = asyncio.run(asyncio.wait_for(_run(), timeout=2.0))
        assert len(events) == 1
        assert "new error" in events[0].message

    def test_multiple_new_lines(self, tmp_path: Path):
        log = tmp_path / "app.log"
        _write(log, "existing\n")

        adapter = TailAdapter(log, from_start=False, poll_interval=0.05)

        async def _run():
            async def _append():
                await asyncio.sleep(0.1)
                _write(log, "line one\nline two\nline three\n", append=True)

            task = asyncio.create_task(_append())
            events = await _collect(adapter, 3, timeout=2.0)
            task.cancel()
            return events

        events = asyncio.run(_run())
        assert len(events) == 3


# ---------------------------------------------------------------------------
# TailAdapter — file rotation / truncation
# ---------------------------------------------------------------------------


class TestTailAdapterRotation:
    def test_detects_truncation(self, tmp_path: Path):
        """Adapter should continue after the file is truncated to 0."""
        log = tmp_path / "app.log"
        _write(log, "first line\n")

        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)

        async def _run():
            events = []

            async def _truncate_then_write():
                await asyncio.sleep(0.1)
                _write(log, "")  # truncate
                await asyncio.sleep(0.1)
                _write(log, "after rotation\n")  # new content

            task = asyncio.create_task(_truncate_then_write())
            # Collect: 1 from original + 1 after truncation
            async for ev in adapter.events():
                events.append(ev)
                if len(events) >= 2:
                    break
            task.cancel()
            return events

        events = asyncio.run(asyncio.wait_for(_run(), timeout=3.0))
        assert len(events) == 2
        assert "after rotation" in events[-1].message

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="Windows locks open files — unlink() while adapter holds handle not possible",
    )
    def test_waits_for_file_to_reappear(self, tmp_path: Path):
        """Adapter should wait when the file disappears and resume on reappear."""
        log = tmp_path / "app.log"
        _write(log, "")

        adapter = TailAdapter(log, from_start=False, poll_interval=0.05)

        async def _run():
            events = []

            async def _delete_recreate():
                await asyncio.sleep(0.1)
                log.unlink()
                await asyncio.sleep(0.15)
                _write(log, "reappeared line\n")

            task = asyncio.create_task(_delete_recreate())
            async for ev in adapter.events():
                events.append(ev)
                break
            task.cancel()
            return events

        events = asyncio.run(asyncio.wait_for(_run(), timeout=3.0))
        assert len(events) == 1
        assert "reappeared" in events[0].message


# ---------------------------------------------------------------------------
# TailAdapter — format detection
# ---------------------------------------------------------------------------


class TestTailAdapterFormatDetection:
    def test_detect_on_empty_file_does_not_raise(self, tmp_path: Path):
        log = tmp_path / "empty.log"
        _write(log, "")
        adapter = TailAdapter(log, from_start=True)
        fmt = adapter._detect_format()
        assert fmt is not None  # returns a LogFormat enum value

    def test_detect_on_missing_file_does_not_raise(self, tmp_path: Path):
        log = tmp_path / "missing.log"
        adapter = TailAdapter(log, from_start=True)
        fmt = adapter._detect_format()
        assert fmt is not None

    def test_detects_json(self, tmp_path: Path):
        from logatory.parsers.detector import LogFormat

        log = tmp_path / "app.log"
        _write(log, json.dumps({"level": "INFO", "msg": "hi"}) + "\n")
        adapter = TailAdapter(log, from_start=True)
        assert adapter._detect_format() == LogFormat.JSON_LINES

    def test_detects_logfmt(self, tmp_path: Path):
        from logatory.parsers.detector import LogFormat

        log = tmp_path / "app.log"
        _write(log, "level=info msg=started port=8080\nlevel=warn msg=slow ms=210\n")
        adapter = TailAdapter(log, from_start=True)
        assert adapter._detect_format() == LogFormat.LOGFMT

    def test_detects_cef(self, tmp_path: Path):
        from logatory.parsers.detector import LogFormat

        log = tmp_path / "app.log"
        _write(log, "CEF:0|V|FW|1.0|100|blocked|8|src=10.0.0.1 dst=8.8.8.8\n")
        adapter = TailAdapter(log, from_start=True)
        assert adapter._detect_format() == LogFormat.CEF


# ---------------------------------------------------------------------------
# TailAdapter — construction defaults
# ---------------------------------------------------------------------------


class TestTailAdapterDefaults:
    def test_default_poll_interval(self, tmp_path: Path):
        adapter = TailAdapter(tmp_path / "x.log")
        assert adapter.poll_interval > 0
        assert adapter.from_start is False

    def test_logfmt_fields_parsed_from_tail(self, tmp_path: Path):
        log = tmp_path / "app.log"
        _write(log, "level=error msg=db_down attempt=3 service=api\n")
        adapter = TailAdapter(log, from_start=True, poll_interval=0.05)
        events = asyncio.run(_collect(adapter, 1))
        assert len(events) == 1
        assert events[0].parsed_fields["service"] == "api"
        assert events[0].message == "db_down"


# ---------------------------------------------------------------------------
# meets_alert_severity
# ---------------------------------------------------------------------------


class TestMeetsAlertSeverity:
    def test_critical_meets_high(self):
        assert meets_alert_severity(_finding(FindingSeverity.CRITICAL), "high") is True

    def test_high_meets_high(self):
        assert meets_alert_severity(_finding(FindingSeverity.HIGH), "high") is True

    def test_medium_does_not_meet_high(self):
        assert meets_alert_severity(_finding(FindingSeverity.MEDIUM), "high") is False

    def test_low_meets_low(self):
        assert meets_alert_severity(_finding(FindingSeverity.LOW), "low") is True

    def test_case_insensitive_min_severity(self):
        assert meets_alert_severity(_finding(FindingSeverity.HIGH), "HIGH") is True

    def test_unknown_min_defaults_to_high(self):
        assert meets_alert_severity(_finding(FindingSeverity.MEDIUM), "nonsense") is False
        assert meets_alert_severity(_finding(FindingSeverity.HIGH), "nonsense") is True


# ---------------------------------------------------------------------------
# post_webhook — non-fatal failure
# ---------------------------------------------------------------------------


class TestPostWebhook:
    def test_unreachable_url_does_not_raise(self):
        """Webhook failures must never propagate to the caller."""
        finding = _finding()
        # Should silently swallow the connection error
        post_webhook("http://localhost:19999/nonexistent", finding)

    def test_invalid_url_does_not_raise(self):
        finding = _finding()
        post_webhook("not-a-url", finding)

    def test_sends_correct_json(self, tmp_path: Path):
        """Verify the payload structure using a minimal HTTP server."""
        import http.server
        import threading

        received: list[bytes] = []

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                received.append(self.rfile.read(length))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):  # suppress server output
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.handle_request)
        thread.start()

        finding = _finding(FindingSeverity.CRITICAL)
        post_webhook(f"http://127.0.0.1:{port}/hook", finding)
        thread.join(timeout=2)

        assert len(received) == 1
        payload = json.loads(received[0])
        assert payload["rule_id"] == "TEST"
        assert payload["severity"] == "critical"
        assert "timestamp" in payload
