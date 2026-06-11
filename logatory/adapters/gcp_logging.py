"""GCP Cloud Logging source adapter — reads entries via the `gcloud` CLI.

If your workloads log to Google Cloud, this adapter pulls entries straight
through `gcloud logging read` — no Python google-cloud dependency, your
active `gcloud` account, ADC and project all apply unchanged. Read-only.

Entries are selected with a Cloud Logging filter (and a freshness window).
Each entry already carries an authoritative timestamp and severity, which are
mapped onto Logatory's model; the message comes from ``textPayload`` (or a
JSON/proto payload, rendered compactly).
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import SourceAdapter

# Cloud Logging severities → Logatory severity.
_SEVERITY_MAP: dict[str, Severity] = {
    "DEFAULT": Severity.INFO,
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "NOTICE": Severity.INFO,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "CRITICAL": Severity.CRITICAL,
    "ALERT": Severity.CRITICAL,
    "EMERGENCY": Severity.CRITICAL,
}


def _parse_ts(value: str | None) -> datetime | None:
    """Parse an RFC3339 timestamp as emitted by Cloud Logging."""
    if not value or not isinstance(value, str):
        return None
    token = value.strip().replace("Z", "+00:00")
    token = re.sub(r"(\.\d{6})\d+", r"\1", token)  # microseconds is datetime's limit
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _rfc3339(dt: datetime) -> str:
    """Render a datetime as the RFC3339 string a Cloud Logging filter wants."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GCPLoggingAdapter(SourceAdapter):
    """Reads log entries from GCP Cloud Logging via the `gcloud` CLI."""

    def __init__(
        self,
        *,
        log_filter: str | None = None,
        project: str | None = None,
        since: str | None = "1h",
        limit: int = 1000,
        runner=None,
    ) -> None:
        self._filter = log_filter
        self._project = project
        self._since = since
        self._limit = limit
        self._runner = runner  # injectable for tests: (list[str]) -> str

    # -- gcloud command construction ---------------------------------------

    def _read_args(self, *, extra_filter: str | None, use_freshness: bool) -> list[str]:
        clauses = [c for c in (self._filter, extra_filter) if c]
        combined = " AND ".join(f"({c})" for c in clauses)

        args = ["gcloud", "logging", "read"]
        if combined:
            args.append(combined)
        args += ["--format", "json", "--limit", str(self._limit)]
        if self._project:
            args += ["--project", self._project]
        if use_freshness and self._since:
            args += ["--freshness", self._since]
        return args

    # -- runner (real subprocess; overridable for tests) -------------------

    def _run(self, args: list[str]) -> str:
        if self._runner is not None:
            return self._runner(args)
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError(
                "gcloud CLI not found — install the Google Cloud SDK to use the gcp adapter."
            )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"gcloud failed: {detail}")
        return result.stdout

    def _fetch(self, *, extra_filter: str | None, use_freshness: bool) -> list[dict]:
        output = self._run(self._read_args(extra_filter=extra_filter, use_freshness=use_freshness))
        try:
            data = json.loads(output) if output.strip() else []
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        # gcloud returns newest-first; reverse to deliver oldest-first.
        return [e for e in reversed(data) if isinstance(e, dict)]

    # -- event construction ------------------------------------------------

    @staticmethod
    def _message(entry: dict) -> str | None:
        if isinstance(entry.get("textPayload"), str):
            return entry["textPayload"]
        payload = entry.get("jsonPayload")
        if isinstance(payload, dict):
            for key in ("message", "msg", "log"):
                if isinstance(payload.get(key), str):
                    return payload[key]
            return json.dumps(payload, default=str)
        if entry.get("protoPayload") is not None:
            return json.dumps(entry["protoPayload"], default=str)
        return None

    def _source_name(self, entry: dict) -> str:
        resource = entry.get("resource")
        if isinstance(resource, dict) and resource.get("type"):
            return str(resource["type"])
        log_name = entry.get("logName")
        if isinstance(log_name, str) and log_name:
            return log_name.rsplit("/", 1)[-1]
        return "gcp"

    def _to_event(self, entry: dict) -> Event | None:
        message = self._message(entry)
        if message is None:
            return None
        severity = _SEVERITY_MAP.get(str(entry.get("severity", "")).upper(), Severity.INFO)
        fields: dict = {}
        if entry.get("logName"):
            fields["log_name"] = entry["logName"]
        if entry.get("insertId"):
            fields["insert_id"] = entry["insertId"]
        resource = entry.get("resource")
        if isinstance(resource, dict) and resource.get("type"):
            fields["resource_type"] = resource["type"]
        if entry.get("severity"):
            fields["gcp_severity"] = entry["severity"]
        return Event(
            raw=json.dumps(entry, default=str),
            source=self._source_name(entry),
            message=message,
            timestamp=_parse_ts(entry.get("timestamp")),
            severity=severity,
            parsed_fields=fields,
        )

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield every matching entry once (batch mode)."""
        for entry in self._fetch(extra_filter=None, use_freshness=True):
            event = self._to_event(entry)
            if event is not None:
                yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll Cloud Logging forever, yielding only newly-arrived entries.

        After the first round a ``timestamp > "…"`` clause is AND-ed onto the
        filter to fetch only newer entries; the inclusive boundary is covered
        by de-duplicating on each entry's insertId. Runs until the caller
        stops iterating.
        """
        cursor: datetime | None = None
        seen: set[str] = set()

        while True:
            extra = f'timestamp > "{_rfc3339(cursor)}"' if cursor else None
            entries = self._fetch(extra_filter=extra, use_freshness=cursor is None)
            newest = cursor
            for entry in entries:
                iid = entry.get("insertId")
                if iid and iid in seen:
                    continue
                event = self._to_event(entry)
                if event is None:
                    continue
                if iid:
                    seen.add(iid)
                yield event
                ts = _parse_ts(entry.get("timestamp"))
                if ts is not None and (newest is None or ts > newest):
                    newest = ts
            if newest is not None:
                cursor = newest
            if len(seen) > 10_000:
                seen.clear()
            await asyncio.sleep(interval)
