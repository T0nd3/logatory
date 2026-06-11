from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from ..models import Event, Severity
from ._polling import HttpPollingAdapter
from .opensearch_config import (
    FieldMapping,
    OpenSearchAuth,
    OpenSearchQuery,
    TimeRange,
    build_query_dsl,
)

_SEVERITY_MAP = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "err": Severity.ERROR,
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}


def _require_opensearch():
    try:
        import opensearchpy

        return opensearchpy
    except ImportError:
        raise ImportError("opensearch-py is not installed. Run: pip install logatory[opensearch]")


def _make_client(
    host: str, port: int, use_ssl: bool, verify_certs: bool, auth: OpenSearchAuth | None
):
    os_mod = _require_opensearch()
    OpenSearch = os_mod.OpenSearch

    http_auth = None
    headers = {}
    ssl_kwargs: dict = {}

    if auth:
        if auth.username and auth.password:
            http_auth = (auth.username, auth.password)
        elif auth.api_key:
            # "id:key" → base64 or raw value depending on server version
            headers["Authorization"] = f"ApiKey {auth.api_key}"
        ssl_kwargs["ca_certs"] = auth.ca_certs
        if auth.client_cert:
            ssl_kwargs["client_cert"] = auth.client_cert
            ssl_kwargs["client_key"] = auth.client_key

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=http_auth,
        headers=headers or None,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        **{k: v for k, v in ssl_kwargs.items() if v is not None},
    )


def _get_nested(doc: dict, dotted_key: str) -> Any:
    """Resolve a dot-notation key from a nested dict. Returns None if missing."""
    parts = dotted_key.split(".")
    node: Any = doc
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _map_timestamp(raw: Any) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        try:
            ms = raw if raw > 1e10 else raw * 1000
            return datetime.fromtimestamp(ms / 1000, tz=UTC)
        except (OSError, ValueError, OverflowError):
            return None
    if isinstance(raw, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt
            except ValueError:
                pass
    return None


def _map_hit(hit: dict, mapping: FieldMapping, index: str) -> Event | None:
    source = hit.get("_source", {})
    if not source:
        return None

    raw_msg = _get_nested(source, mapping.message)
    message = str(raw_msg) if raw_msg is not None else ""
    if not message:
        return None

    timestamp = _map_timestamp(_get_nested(source, mapping.timestamp))

    severity = Severity.INFO
    if mapping.severity:
        sev_raw = _get_nested(source, mapping.severity)
        if sev_raw:
            severity = _SEVERITY_MAP.get(str(sev_raw).lower(), Severity.INFO)

    source_name = index
    if mapping.source_name:
        sn = _get_nested(source, mapping.source_name)
        if sn:
            source_name = str(sn)

    # Everything in _source goes into parsed_fields; also carry the document
    # _id so realtime polling can deduplicate across overlapping queries.
    parsed_fields = {k: v for k, v in source.items() if isinstance(v, (str, int, float, bool))}
    doc_id = hit.get("_id")
    if doc_id is not None:
        parsed_fields["_id"] = doc_id

    return Event(
        raw=message,
        source=source_name,
        message=message,
        timestamp=timestamp,
        severity=severity,
        parsed_fields=parsed_fields,
    )


class OpenSearchAdapter(HttpPollingAdapter):
    """Reads log events from an OpenSearch index via search_after pagination.

    Read-only — uses API keys or credentials without write permissions.
    Install the optional dependency first: pip install logatory[opensearch]
    """

    def __init__(
        self,
        host: str,
        port: int,
        query: OpenSearchQuery,
        auth: OpenSearchAuth | None = None,
        use_ssl: bool = False,
        verify_certs: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._query = query
        self._auth = auth
        self._use_ssl = use_ssl
        self._verify_certs = verify_certs
        self._client_instance = None  # reused across poll rounds, built lazily

    def _client(self):
        if self._client_instance is None:
            self._client_instance = _make_client(
                self._host, self._port, self._use_ssl, self._verify_certs, self._auth
            )
        return self._client_instance

    def _fetch(self, client, query: OpenSearchQuery) -> list[Event]:
        """Run one paginated search and return all matching events."""
        dsl = build_query_dsl(query)
        mapping = query.field_mapping
        index = query.index
        page_size = query.page_size
        max_events = query.max_events
        out: list[Event] = []
        search_after: list | None = None

        while True:
            body = {**dsl, "size": page_size}
            if search_after:
                body["search_after"] = search_after

            response = client.search(index=index, body=body)
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                break

            for hit in hits:
                event = _map_hit(hit, mapping, index)
                if event is not None:
                    out.append(event)
                    if max_events is not None and len(out) >= max_events:
                        return out

            # Advance the cursor to the sort values of the last hit
            search_after = hits[-1].get("sort")
            if not search_after or len(hits) < page_size:
                break

        return out

    # -- polling hooks -----------------------------------------------------
    #
    # Each realtime round queries for events at or after the newest timestamp
    # seen so far and skips documents already delivered (by `_id`), so events
    # on the timestamp boundary are neither dropped nor sent twice. The
    # ``_fetch`` paginator already returns mapped Events, so items are Events.

    def _fetch_batch(self, cursor: datetime | None) -> list[Event]:
        if cursor is None:
            query = self._query
        else:
            query = replace(self._query, time_range=TimeRange(since=cursor.isoformat()))
        return self._fetch(self._client(), query)

    def _make_event(self, event: Event) -> Event:
        return event

    def _dedup_key(self, event: Event) -> str | None:
        doc_id = event.parsed_fields.get("_id")
        return str(doc_id) if doc_id is not None else None

    def _advance_cursor(
        self, cursor: datetime | None, event_item: Event, event: Event | None
    ) -> datetime | None:
        if event is None or event.timestamp is None:
            return cursor
        if cursor is None or event.timestamp > cursor:
            return event.timestamp
        return cursor
