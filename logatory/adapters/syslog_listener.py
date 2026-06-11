"""Syslog listener source adapter — receives syslog over UDP/TCP.

Network devices, firewalls, routers and appliances rarely write a log file
you can read — they *emit* syslog over the wire (RFC 3164, the old BSD
format, or RFC 5424, the modern one). This adapter binds a UDP and/or TCP
port and turns every incoming syslog message into a normalized Event, so a
box that only speaks syslog becomes just another source.

The PRI value yields the syslog facility and severity (mapped onto Logatory's
severity levels); the timestamp, hostname and app/tag are parsed out and the
remaining text becomes the message. Messages that don't look like syslog are
still delivered verbatim. Like ``stdin`` and ``tail`` this is a local,
stream-only source — it isn't a per-host fleet target.

TCP framing follows RFC 6587: octet-counting (``<len> <msg>``) when a frame
starts with a digit, otherwise newline-delimited (non-transparent framing).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import SourceAdapter

# Syslog severity (the low 3 bits of PRI) → Logatory severity.
#   0 Emergency 1 Alert 2 Critical 3 Error 4 Warning 5 Notice 6 Info 7 Debug
_SEVERITY_MAP: dict[int, Severity] = {
    0: Severity.CRITICAL,
    1: Severity.CRITICAL,
    2: Severity.CRITICAL,
    3: Severity.ERROR,
    4: Severity.WARNING,
    5: Severity.INFO,
    6: Severity.INFO,
    7: Severity.DEBUG,
}

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

_PRI_RE = re.compile(r"^<(\d{1,3})>")
# RFC 5424: <PRI>VERSION SP TIMESTAMP SP HOST SP APP SP PROCID SP MSGID SP ...
_RFC5424_HEAD = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d) (?P<ts>\S+) (?P<host>\S+) "
    r"(?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$",
    re.DOTALL,
)
# RFC 3164: <PRI>Mmm d hh:mm:ss HOST TAG[pid]: message
_RFC3164_HEAD = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<rest>.*)$",
    re.DOTALL,
)
_TAG_RE = re.compile(r"^(?P<tag>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$", re.DOTALL)


def _decode_pri(pri: int) -> tuple[int, int, Severity]:
    """Split a PRI value into (facility, syslog_severity, mapped_severity)."""
    facility, severity = divmod(pri, 8)
    return facility, severity, _SEVERITY_MAP.get(severity, Severity.INFO)


def _parse_5424_ts(token: str) -> datetime | None:
    if token == "-":
        return None
    token = token.replace("Z", "+00:00")
    token = re.sub(r"(\.\d{6})\d+", r"\1", token)  # microseconds is datetime's limit
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _parse_3164_ts(token: str) -> datetime | None:
    parts = token.split()
    if len(parts) != 3:
        return None
    month = _MONTHS.get(parts[0])
    if not month:
        return None
    try:
        day = int(parts[1])
        h, m, s = (int(x) for x in parts[2].split(":"))
    except ValueError:
        return None
    # BSD syslog omits the year — assume the current one.
    return datetime(datetime.now(tz=UTC).year, month, day, h, m, s, tzinfo=UTC)


def _split_structured_data(rest: str) -> tuple[str, str]:
    """Split an RFC 5424 SD-and-MSG tail into (structured_data, message)."""
    if rest.startswith("-"):  # NILVALUE
        return "-", rest[1:].lstrip()
    if not rest.startswith("["):
        return "", rest
    depth = 0
    i = 0
    while i < len(rest):
        ch = rest[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0 and (i + 1 >= len(rest) or rest[i + 1] != "["):
                return rest[: i + 1], rest[i + 1 :].lstrip()
        i += 1
    return rest, ""


def parse_syslog(raw: str, *, peer: str | None = None) -> Event:
    """Parse one syslog message (RFC 5424 or RFC 3164) into an Event.

    Anything that doesn't start with a ``<PRI>`` — or doesn't match either
    framing — is still returned as a plaintext Event so nothing is dropped.
    """
    text = raw.strip()
    fields: dict[str, object] = {}
    if peer:
        fields["peer"] = peer

    pri_match = _PRI_RE.match(text)
    if pri_match:
        facility, sys_sev, severity = _decode_pri(int(pri_match.group(1)))
        fields["facility"] = facility
        fields["syslog_severity"] = sys_sev
    else:
        # No PRI — not syslog framing. Deliver as-is.
        return Event(raw=raw, source=peer or "syslog", message=text, severity=Severity.INFO)

    m5 = _RFC5424_HEAD.match(text)
    if m5:
        host = m5.group("host")
        if host != "-":
            fields["host"] = host
        if m5.group("app") != "-":
            fields["app_name"] = m5.group("app")
        if m5.group("procid") != "-":
            fields["procid"] = m5.group("procid")
        if m5.group("msgid") != "-":
            fields["msgid"] = m5.group("msgid")
        sd, message = _split_structured_data(m5.group("rest"))
        if sd and sd != "-":
            fields["structured_data"] = sd
        return Event(
            raw=raw,
            source=host if host != "-" else (peer or "syslog"),
            message=message,
            timestamp=_parse_5424_ts(m5.group("ts")),
            severity=severity,
            parsed_fields=fields,
        )

    m3 = _RFC3164_HEAD.match(text)
    if m3:
        host = m3.group("host")
        fields["host"] = host
        rest = m3.group("rest")
        tag = _TAG_RE.match(rest)
        if tag:
            fields["app_name"] = tag.group("tag")
            if tag.group("pid"):
                fields["procid"] = tag.group("pid")
            message = tag.group("msg")
        else:
            message = rest
        return Event(
            raw=raw,
            source=host,
            message=message,
            timestamp=_parse_3164_ts(m3.group("ts")),
            severity=severity,
            parsed_fields=fields,
        )

    # Had a PRI but no recognizable header — keep the body after <PRI>.
    return Event(
        raw=raw,
        source=peer or "syslog",
        message=text[pri_match.end() :],
        severity=severity,
        parsed_fields=fields,
    )


def _iter_tcp_frames(buffer: str) -> tuple[list[str], str]:
    """Pull complete frames out of a TCP buffer; return (frames, remainder).

    Supports RFC 6587 octet-counting (``<len> <msg>``) and the common
    newline-delimited (non-transparent) framing.
    """
    frames: list[str] = []
    while buffer:
        if buffer[0].isdigit():
            sp = buffer.find(" ")
            if sp == -1:
                break  # length prefix not complete yet
            length_token = buffer[:sp]
            if not length_token.isdigit():
                # Not really octet-counting — fall back to newline framing.
                nl = buffer.find("\n")
                if nl == -1:
                    break
                frames.append(buffer[:nl])
                buffer = buffer[nl + 1 :]
                continue
            length = int(length_token)
            start = sp + 1
            if len(buffer) - start < length:
                break  # whole message not arrived yet
            frames.append(buffer[start : start + length])
            buffer = buffer[start + length :]
        else:
            nl = buffer.find("\n")
            if nl == -1:
                break
            frames.append(buffer[:nl])
            buffer = buffer[nl + 1 :]
    return frames, buffer


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Datagram handler — each packet is one syslog message."""

    def __init__(self, adapter: SyslogListenerAdapter) -> None:
        self._adapter = adapter

    def datagram_received(self, data: bytes, addr) -> None:
        text = data.decode("utf-8", errors="replace")
        peer = addr[0] if addr else None
        for line in text.splitlines() or [text]:
            if line.strip():
                self._adapter._enqueue(parse_syslog(line, peer=peer))


class SyslogListenerAdapter(SourceAdapter):
    """Receives syslog messages over UDP and/or TCP and yields Events.

    A local, stream-only source: it never "completes", so it's used through
    ``poll`` (follow forever) or ``events`` bounded by ``max_messages``.
    """

    def __init__(
        self,
        *,
        host: str = "0.0.0.0",
        port: int = 514,
        protocol: str = "udp",
        max_messages: int | None = None,
        queue_size: int = 10_000,
    ) -> None:
        proto = protocol.lower()
        if proto not in ("udp", "tcp", "both"):
            raise ValueError("protocol must be 'udp', 'tcp' or 'both'.")
        self._host = host
        self._port = port
        self._protocol = proto
        self._max_messages = max_messages
        self._queue_size = queue_size
        self._queue: asyncio.Queue[Event] | None = None
        self._transports: list[asyncio.BaseTransport] = []
        self._server: asyncio.AbstractServer | None = None
        self.dropped = 0

    @property
    def bound_port(self) -> int:
        """The actually-bound port (useful when constructed with port 0)."""
        return self._port

    def _enqueue(self, event: Event) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1  # listener outpacing the consumer — shed load

    async def _on_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer_info = writer.get_extra_info("peername")
        peer = peer_info[0] if peer_info else None
        buffer = ""
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", errors="replace")
                frames, buffer = _iter_tcp_frames(buffer)
                for frame in frames:
                    if frame.strip():
                        self._enqueue(parse_syslog(frame, peer=peer))
            if buffer.strip():  # trailing frame without a newline
                self._enqueue(parse_syslog(buffer, peer=peer))
        finally:
            writer.close()

    async def _start(self) -> None:
        loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(self._queue_size)
        if self._protocol in ("udp", "both"):
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _SyslogUDPProtocol(self),
                local_addr=(self._host, self._port),
            )
            self._transports.append(transport)
            self._port = transport.get_extra_info("sockname")[1]
        if self._protocol in ("tcp", "both"):
            self._server = await asyncio.start_server(self._on_tcp_client, self._host, self._port)
            self._port = self._server.sockets[0].getsockname()[1]

    async def _stop(self) -> None:
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _messages(self) -> AsyncIterator[Event]:
        await self._start()
        try:
            while True:
                assert self._queue is not None
                yield await self._queue.get()
        finally:
            await self._stop()

    async def events(self) -> AsyncIterator[Event]:
        """Listen and yield events, stopping after ``max_messages`` if set."""
        count = 0
        async for event in self._messages():
            yield event
            count += 1
            if self._max_messages is not None and count >= self._max_messages:
                break

    async def poll(self, interval: float = 0.0) -> AsyncIterator[Event]:
        """Listen forever, yielding each message as it arrives.

        ``interval`` is accepted for interface parity with the polling
        adapters but unused — syslog is push-based, not polled.
        """
        async for event in self._messages():
            yield event
