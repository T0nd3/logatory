from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class OpenSearchAuth:
    """Authentication config for OpenSearch. Set exactly one of the auth fields."""

    # Basic auth
    username: str | None = None
    password: str | None = None
    # API Key — format: "key_id:api_key" or just the encoded key
    api_key: str | None = None
    # Certificate auth
    client_cert: str | None = None
    client_key: str | None = None
    # CA bundle for server cert verification
    ca_certs: str | None = None

    @classmethod
    def from_env(cls) -> OpenSearchAuth:
        import os

        return cls(
            username=os.environ.get("OPENSEARCH_USERNAME"),
            password=os.environ.get("OPENSEARCH_PASSWORD"),
            api_key=os.environ.get("OPENSEARCH_API_KEY"),
            client_cert=os.environ.get("OPENSEARCH_CLIENT_CERT"),
            client_key=os.environ.get("OPENSEARCH_CLIENT_KEY"),
            ca_certs=os.environ.get("OPENSEARCH_CA_CERTS"),
        )


@dataclass
class FieldMapping:
    """Maps OpenSearch document fields to the internal Event schema.

    Supports dot-notation for nested fields, e.g. 'log.level' or '@timestamp'.
    """

    timestamp: str = "@timestamp"
    message: str = "message"
    severity: str | None = "level"  # None = don't extract
    source_name: str | None = "host.name"  # used as event.source


@dataclass
class TimeRange:
    since: str | None = None  # "24h", "7d", "2026-05-18T00:00:00Z"
    until: str | None = None  # "now", ISO datetime


@dataclass
class OpenSearchQuery:
    index: str = "logstash-*"
    time_range: TimeRange = field(default_factory=TimeRange)
    # Extra field filters: each entry is {"field": "...", "value": "..."}
    filters: list[dict[str, str]] = field(default_factory=list)
    field_mapping: FieldMapping = field(default_factory=FieldMapping)
    page_size: int = 1000
    max_events: int | None = None  # None = fetch all matching


_RELATIVE_RE = re.compile(r"^(\d+)([smhd])$")


def _to_os_time(value: str) -> str:
    """Convert a user-supplied time string to an OpenSearch time expression.

    '24h' → 'now-24h'   '7d' → 'now-7d'   ISO strings → passed through
    """
    if _RELATIVE_RE.match(value):
        return f"now-{value}"
    return value


def build_query_dsl(query: OpenSearchQuery) -> dict:
    """Translate an OpenSearchQuery into an OpenSearch query DSL body."""
    must: list[dict] = []
    ts_field = query.field_mapping.timestamp

    # Time range filter
    range_clause: dict = {}
    if query.time_range.since:
        range_clause["gte"] = _to_os_time(query.time_range.since)
    if query.time_range.until:
        range_clause["lte"] = _to_os_time(query.time_range.until)
    if range_clause:
        must.append({"range": {ts_field: range_clause}})

    # Exact-value filters
    must.extend({"term": {f["field"]: f["value"]}} for f in query.filters)

    query_clause: dict = {"match_all": {}} if not must else {"bool": {"must": must}}

    return {
        "query": query_clause,
        "sort": [
            {ts_field: {"order": "asc"}},
            {"_id": {"order": "asc"}},  # tiebreaker for stable search_after
        ],
    }
