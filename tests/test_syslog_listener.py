"""Tests for the syslog listener source adapter."""

from __future__ import annotations

import asyncio
import socket

import pytest

from logatory.adapters.syslog_listener import (
    SyslogListenerAdapter,
    _decode_pri,
    _iter_tcp_frames,
    _split_structured_data,
    _SyslogUDPProtocol,
    parse_syslog,
)
from logatory.models import Severity

# ---------------------------------------------------------------------------
# PRI decoding
# ---------------------------------------------------------------------------


class TestDecodePri:
    def test_facility_and_severity(self):
        # <34> = facility 4 (auth), severity 2 (Critical)
        facility, sev, mapped = _decode_pri(34)
        assert facility == 4
        assert sev == 2
        assert mapped == Severity.CRITICAL

    def test_severity_mapping(self):
        cases = {
            0: Severity.CRITICAL,
            3: Severity.ERROR,
            4: Severity.WARNING,
            6: Severity.INFO,
            7: Severity.DEBUG,
        }
        for sys_sev, expected in cases.items():
            _, _, mapped = _decode_pri(sys_sev)  # facility 0
            assert mapped == expected, f"severity {sys_sev}"


# ---------------------------------------------------------------------------
# RFC 3164 (BSD) parsing
# ---------------------------------------------------------------------------


class TestParse3164:
    def test_classic_message(self):
        ev = parse_syslog("<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick")
        assert ev.severity == Severity.CRITICAL
        assert ev.parsed_fields["host"] == "mymachine"
        assert ev.parsed_fields["app_name"] == "su"
        assert ev.message == "'su root' failed for lonvick"
        assert ev.source == "mymachine"
        assert ev.timestamp is not None and ev.timestamp.month == 10

    def test_tag_with_pid(self):
        ev = parse_syslog("<13>Jan  5 09:00:00 web01 nginx[1234]: GET / 200")
        assert ev.parsed_fields["app_name"] == "nginx"
        assert ev.parsed_fields["procid"] == "1234"
        assert ev.message == "GET / 200"


# ---------------------------------------------------------------------------
# RFC 5424 parsing
# ---------------------------------------------------------------------------


class TestParse5424:
    def test_full_message_with_nil_sd(self):
        ev = parse_syslog(
            "<165>1 2026-06-11T22:14:15.003Z host.example.com evntslog 9 ID47 - "
            "an application event log entry"
        )
        assert ev.parsed_fields["host"] == "host.example.com"
        assert ev.parsed_fields["app_name"] == "evntslog"
        assert ev.parsed_fields["procid"] == "9"
        assert ev.parsed_fields["msgid"] == "ID47"
        assert ev.message == "an application event log entry"
        assert ev.timestamp is not None and ev.timestamp.year == 2026
        assert "structured_data" not in ev.parsed_fields

    def test_structured_data_extracted(self):
        ev = parse_syslog(
            "<165>1 2026-06-11T22:14:15Z host app - - "
            '[exampleSDID@32473 iut="3" eventID="1011"] the message here'
        )
        assert ev.parsed_fields["structured_data"] == '[exampleSDID@32473 iut="3" eventID="1011"]'
        assert ev.message == "the message here"

    def test_nil_host_falls_back_to_peer(self):
        ev = parse_syslog("<165>1 - - - - - - hello", peer="10.0.0.5")
        assert ev.source == "10.0.0.5"
        assert ev.message == "hello"
        assert ev.timestamp is None  # nil timestamp


# ---------------------------------------------------------------------------
# Non-syslog / malformed input
# ---------------------------------------------------------------------------


class TestParseFallback:
    def test_no_pri_delivered_verbatim(self):
        ev = parse_syslog("just a plain log line", peer="1.2.3.4")
        assert ev.message == "just a plain log line"
        assert ev.source == "1.2.3.4"
        assert ev.severity == Severity.INFO

    def test_pri_only_keeps_body(self):
        ev = parse_syslog("<14>this has a pri but no header", peer="1.2.3.4")
        assert ev.message == "this has a pri but no header"
        assert ev.parsed_fields["facility"] == 1


# ---------------------------------------------------------------------------
# Structured-data splitting
# ---------------------------------------------------------------------------


class TestSplitStructuredData:
    def test_nil(self):
        assert _split_structured_data("- the msg") == ("-", "the msg")

    def test_single_element(self):
        sd, msg = _split_structured_data('[a@1 k="v"] hello')
        assert sd == '[a@1 k="v"]'
        assert msg == "hello"

    def test_multiple_elements(self):
        sd, msg = _split_structured_data('[a@1 k="v"][b@2 x="y"] body')
        assert sd == '[a@1 k="v"][b@2 x="y"]'
        assert msg == "body"

    def test_no_sd(self):
        assert _split_structured_data("plain message") == ("", "plain message")


# ---------------------------------------------------------------------------
# TCP framing
# ---------------------------------------------------------------------------


class TestTcpFrames:
    def test_newline_framing(self):
        frames, rest = _iter_tcp_frames("msg one\nmsg two\npartial")
        assert frames == ["msg one", "msg two"]
        assert rest == "partial"

    def test_octet_counting(self):
        # Two back-to-back octet-counted frames.
        frames, rest = _iter_tcp_frames("11 hello world5 again")
        assert frames == ["hello world", "again"]
        assert rest == ""

    def test_octet_counting_complete(self):
        frames, rest = _iter_tcp_frames("5 hello")
        assert frames == ["hello"]
        assert rest == ""

    def test_incomplete_octet_frame_buffered(self):
        frames, rest = _iter_tcp_frames("20 not yet complete")
        assert frames == []
        assert rest == "20 not yet complete"


# ---------------------------------------------------------------------------
# UDP protocol → queue wiring (no real socket)
# ---------------------------------------------------------------------------


class TestUdpProtocol:
    async def test_datagram_enqueues_parsed_events(self):
        adapter = SyslogListenerAdapter(host="127.0.0.1", port=0)
        adapter._queue = asyncio.Queue()
        proto = _SyslogUDPProtocol(adapter)
        proto.datagram_received(b"<34>Oct 11 22:14:15 host su: boom", ("10.0.0.1", 5000))
        event = adapter._queue.get_nowait()
        assert event.parsed_fields["host"] == "host"
        assert event.message == "boom"

    async def test_multiline_datagram_splits(self):
        adapter = SyslogListenerAdapter(host="127.0.0.1", port=0)
        adapter._queue = asyncio.Queue()
        proto = _SyslogUDPProtocol(adapter)
        proto.datagram_received(b"<14>line one\n<14>line two", ("10.0.0.1", 5000))
        assert adapter._queue.qsize() == 2


# ---------------------------------------------------------------------------
# Construction guards
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_invalid_protocol(self):
        with pytest.raises(ValueError, match="protocol"):
            SyslogListenerAdapter(protocol="carrier-pigeon")

    def test_enqueue_drops_when_full(self):
        adapter = SyslogListenerAdapter(host="127.0.0.1", port=0, queue_size=1)
        adapter._queue = asyncio.Queue(1)
        adapter._enqueue(parse_syslog("<14>one"))
        adapter._enqueue(parse_syslog("<14>two"))  # queue full -> dropped
        assert adapter.dropped == 1


# ---------------------------------------------------------------------------
# Real loopback UDP listener (end-to-end)
# ---------------------------------------------------------------------------


class TestLiveUdp:
    async def test_receives_over_the_wire(self):
        adapter = SyslogListenerAdapter(host="127.0.0.1", port=0, protocol="udp")
        await adapter._start()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(
                b"<34>Oct 11 22:14:15 wirehost sshd[42]: login failed",
                ("127.0.0.1", adapter.bound_port),
            )
            sock.close()
            assert adapter._queue is not None
            event = await asyncio.wait_for(adapter._queue.get(), timeout=2.0)
            assert event.parsed_fields["host"] == "wirehost"
            assert event.parsed_fields["app_name"] == "sshd"
            assert event.message == "login failed"
        finally:
            await adapter._stop()

    async def test_events_respects_max_messages(self):
        adapter = SyslogListenerAdapter(host="127.0.0.1", port=0, protocol="udp", max_messages=2)

        async def _collect():
            return [e async for e in adapter.events()]

        task = asyncio.create_task(_collect())
        # Give the listener a moment to bind before sending.
        await asyncio.sleep(0.05)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(3):
            sock.sendto(f"<14>msg {i}".encode(), ("127.0.0.1", adapter.bound_port))
        sock.close()

        events = await asyncio.wait_for(task, timeout=2.0)
        assert len(events) == 2  # stopped at max_messages
