"""AWS CloudWatch Logs source adapter — reads log events via the `aws` CLI.

If your apps ship to CloudWatch, this adapter pulls events straight from a
log group with `aws logs filter-log-events` — no boto3 dependency, your AWS
profile / SSO session / instance role and `~/.aws/config` all apply
unchanged. Read-only.

Events are filtered by log group (optionally specific streams, a CloudWatch
filter pattern, and a lookback window). Each event's message is parsed
exactly like any other source (JSON, logfmt, plaintext, …); CloudWatch's own
millisecond timestamp is used when the message carries none.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter

_LOOKBACK_RE = re.compile(r"^(\d+)\s*([smhd])$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_lookback(value: str | None) -> int | None:
    """Parse a lookback like ``30s`` / ``5m`` / ``1h`` / ``2d`` into seconds."""
    if not value:
        return None
    m = _LOOKBACK_RE.match(value.strip())
    if not m:
        return None
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2)]


def _ms_to_dt(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000, tz=UTC)


class CloudWatchAdapter(SourceAdapter):
    """Reads log events from an AWS CloudWatch log group via the `aws` CLI."""

    def __init__(
        self,
        *,
        log_group: str,
        log_stream: str | list[str] | None = None,
        filter_pattern: str | None = None,
        since: str | None = None,
        region: str | None = None,
        profile: str | None = None,
        limit: int = 1000,
        runner=None,
    ) -> None:
        if not log_group:
            raise ValueError("CloudWatchAdapter needs a 'log_group'.")
        self._log_group = log_group
        if isinstance(log_stream, str):
            log_stream = [log_stream]
        self._log_streams = log_stream
        self._filter_pattern = filter_pattern
        self._since = since
        self._region = region
        self._profile = profile
        self._limit = limit
        self._runner = runner  # injectable for tests: (list[str]) -> str

    # -- aws command construction ------------------------------------------

    def _global_args(self) -> list[str]:
        args: list[str] = []
        if self._region:
            args += ["--region", self._region]
        if self._profile:
            args += ["--profile", self._profile]
        return args

    def _filter_args(self, start_ms: int | None) -> list[str]:
        args = [
            "aws",
            "logs",
            "filter-log-events",
            "--log-group-name",
            self._log_group,
            "--output",
            "json",
            "--limit",
            str(self._limit),
        ]
        if self._log_streams:
            args += ["--log-stream-names", *self._log_streams]
        if self._filter_pattern:
            args += ["--filter-pattern", self._filter_pattern]
        if start_ms is not None:
            args += ["--start-time", str(start_ms)]
        return [*args, *self._global_args()]

    def _start_ms_from_since(self) -> int | None:
        seconds = _parse_lookback(self._since)
        if seconds is None:
            return None
        start = datetime.now(tz=UTC) - timedelta(seconds=seconds)
        return int(start.timestamp() * 1000)

    # -- runner (real subprocess; overridable for tests) -------------------

    def _run(self, args: list[str]) -> str:
        if self._runner is not None:
            return self._runner(args)
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError(
                "aws CLI not found — install the AWS CLI to use the cloudwatch adapter."
            )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"aws failed: {detail}")
        return result.stdout

    def _fetch(self, start_ms: int | None) -> list[dict]:
        output = self._run(self._filter_args(start_ms))
        try:
            data = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []
        events = data.get("events") if isinstance(data, dict) else None
        return [e for e in events if isinstance(e, dict)] if isinstance(events, list) else []

    # -- event construction ------------------------------------------------

    def _source_name(self, obj: dict) -> str:
        stream = obj.get("logStreamName")
        return f"{self._log_group}:{stream}" if stream else self._log_group

    def _to_event(self, parser, obj: dict) -> Event | None:
        message = obj.get("message")
        if message is None:
            return None
        event = parser.parse(message)
        if event is None:
            return None
        event.source = self._source_name(obj)
        ts_ms = obj.get("timestamp")
        if event.timestamp is None and isinstance(ts_ms, (int, float)):
            event.timestamp = _ms_to_dt(int(ts_ms))
        event.parsed_fields["log_group"] = self._log_group
        if obj.get("logStreamName"):
            event.parsed_fields["log_stream"] = obj["logStreamName"]
        if obj.get("eventId"):
            event.parsed_fields["event_id"] = obj["eventId"]
        return event

    def _build_parser(self, events: list[dict]):
        sample = [e["message"] for e in events[:5] if e.get("message")]
        return get_parser(FormatDetector().detect(sample), source=self._log_group)

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield every matching event once (batch mode)."""
        raw = self._fetch(self._start_ms_from_since())
        if not raw:
            return
        parser = self._build_parser(raw)
        for obj in raw:
            event = self._to_event(parser, obj)
            if event is not None:
                yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll the log group forever, yielding only newly-arrived events.

        A millisecond timestamp cursor is advanced each round and passed back
        as ``--start-time``; because that boundary is inclusive, events are
        also de-duplicated by their CloudWatch eventId. Runs until the caller
        stops iterating.
        """
        cursor_ms = self._start_ms_from_since()
        parser = None
        seen: set[str] = set()

        while True:
            raw = self._fetch(cursor_ms)
            if raw and parser is None:
                parser = self._build_parser(raw)
            newest = cursor_ms
            for obj in raw:
                eid = obj.get("eventId")
                if eid and eid in seen:
                    continue
                ts_ms = obj.get("timestamp")
                if cursor_ms is not None and isinstance(ts_ms, (int, float)) and ts_ms < cursor_ms:
                    continue
                event = self._to_event(parser, obj)
                if event is None:
                    continue
                if eid:
                    seen.add(eid)
                yield event
                if isinstance(ts_ms, (int, float)) and (newest is None or ts_ms > newest):
                    newest = int(ts_ms)
            if newest is not None:
                cursor_ms = newest
            # Bound the dedup set so a long-running poll can't grow unbounded.
            if len(seen) > 10_000:
                seen.clear()
            await asyncio.sleep(interval)
