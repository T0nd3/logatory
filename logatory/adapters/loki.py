"""Grafana Loki source adapter — reads logs from a Loki instance over HTTP.

Queries Loki's `query_range` API with a LogQL stream selector. No extra
dependency — uses the standard library HTTP client. Read-only: a viewer
account or token is enough.

Loki stores raw log lines, so each line is run through the format detector
and parsers, exactly like a local file; Loki's own nanosecond timestamp and
stream labels are used to enrich the parsed event.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime

from ..models import Event
from ..parsers.base import BaseParser
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from ._http import basic_auth_header, http_get
from ._polling import HttpPollingAdapter

_QUERY_RANGE = "/loki/api/v1/query_range"
_NS_PER_SECOND = 1_000_000_000


def _ns_to_datetime(ns: int) -> datetime | None:
    try:
        return datetime.fromtimestamp(ns / _NS_PER_SECOND, tz=UTC)
    except (ValueError, OSError, OverflowError):
        return None


class LokiAdapter(HttpPollingAdapter):
    """Reads log events from a Grafana Loki instance via its HTTP query API."""

    def __init__(
        self,
        *,
        url: str = "http://localhost:3100",
        query: str = '{job=~".+"}',
        start_ns: int | None = None,
        limit: int = 1000,
        source_label: str = "job",
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        org_id: str | None = None,
        timeout: float = 30.0,
        fetcher=None,
    ) -> None:
        self._url = url.rstrip("/")
        self._query = query
        self._start_ns = start_ns
        self._limit = limit
        self._source_label = source_label
        self._username = username
        self._password = password
        self._token = token
        self._org_id = org_id
        self._timeout = timeout
        self._fetcher = fetcher  # injectable for tests: (url, headers) -> str
        self._parser: BaseParser | None = None  # built lazily from the first batch's sample

    # -- request construction ----------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        elif self._username and self._password:
            headers["Authorization"] = basic_auth_header(self._username, self._password)
        if self._org_id:
            headers["X-Scope-OrgID"] = self._org_id
        return headers

    def _request_url(self, start_ns: int) -> str:
        params = urllib.parse.urlencode(
            {
                "query": self._query,
                "start": str(start_ns),
                "limit": str(self._limit),
                "direction": "forward",
            }
        )
        return f"{self._url}{_QUERY_RANGE}?{params}"

    def _fetch(self, start_ns: int) -> str:
        url = self._request_url(start_ns)
        headers = self._headers()
        if self._fetcher is not None:
            return self._fetcher(url, headers)
        return http_get(url, headers, timeout=self._timeout)

    def _default_start_ns(self) -> int:
        if self._start_ns is not None:
            return self._start_ns
        return int(datetime.now(tz=UTC).timestamp()) * _NS_PER_SECOND - 3600 * _NS_PER_SECOND

    # -- response mapping --------------------------------------------------

    @staticmethod
    def _entries(payload: str) -> list[tuple[int, str, dict]]:
        """Parse a query_range response into (timestamp_ns, line, labels) tuples."""
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return []
        out: list[tuple[int, str, dict]] = []
        for stream in data.get("data", {}).get("result", []):
            labels = stream.get("stream", {}) or {}
            for value in stream.get("values", []):
                if not isinstance(value, list) or len(value) < 2:
                    continue
                try:
                    ns = int(value[0])
                except (ValueError, TypeError):
                    continue
                out.append((ns, str(value[1]), labels))
        out.sort(key=lambda e: e[0])
        return out

    def _to_event(self, parser, ns: int, line: str, labels: dict) -> Event | None:
        event = parser.parse(line)
        if event is None:
            return None
        if event.timestamp is None:
            event.timestamp = _ns_to_datetime(ns)
        src = labels.get(self._source_label) or labels.get("service_name")
        if src:
            event.source = str(src)
        for key, value in labels.items():
            event.parsed_fields.setdefault(key, value)
        return event

    # -- polling hooks -----------------------------------------------------
    #
    # Loki's `start` is inclusive, so entries on the boundary are skipped by a
    # (timestamp, line) key kept from the previous batch — no duplicates, no
    # gaps. The cursor is the newest nanosecond timestamp seen so far.

    def _initial_cursor(self) -> int:
        return self._default_start_ns()

    def _fetch_batch(self, cursor: int) -> list[tuple[int, str, dict]]:
        return self._entries(self._fetch(cursor))

    def _prepare_batch(self, items: list[tuple[int, str, dict]]) -> None:
        if self._parser is None:
            sample = [line for _, line, _ in items[:5] if line.strip()]
            self._parser = get_parser(FormatDetector().detect(sample), source="loki")

    def _make_event(self, item: tuple[int, str, dict]) -> Event | None:
        ns, line, labels = item
        return self._to_event(self._parser, ns, line, labels)

    def _dedup_key(self, item: tuple[int, str, dict]) -> tuple[int, str]:
        ns, line, _labels = item
        return (ns, line)

    def _advance_cursor(
        self, cursor: int, item: tuple[int, str, dict], event: Event | None
    ) -> int:
        ns = item[0]
        return ns if ns >= cursor else cursor
