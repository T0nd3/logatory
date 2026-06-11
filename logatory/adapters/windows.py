"""Windows Event Log source adapter — reads events from a JSON export.

Windows event logs are most portably consumed as JSON: export them with
PowerShell::

    Get-WinEvent -LogName System -MaxEvents 500 |
        Select-Object TimeCreated,Id,LevelDisplayName,Level,ProviderName,
                      LogName,Message,MachineName,RecordId,Task |
        ConvertTo-Json -Depth 3 > system.json

then analyse the file anywhere — even on Linux — with::

    logatory windows scan --path system.json

On a Windows host the adapter can also fetch events live by shelling out to
PowerShell's ``Get-WinEvent`` itself (``--log System``). Either way each
record is mapped to a normalized Event: the Windows level becomes a severity,
``TimeCreated`` the timestamp, and the provider/log/record metadata is kept
in ``parsed_fields``.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

from ..models import Event, Severity
from .base import SourceAdapter

# Windows Event Log numeric level → internal severity.
_LEVEL_MAP = {
    0: Severity.INFO,  # LogAlways
    1: Severity.CRITICAL,
    2: Severity.ERROR,
    3: Severity.WARNING,
    4: Severity.INFO,
    5: Severity.DEBUG,  # Verbose
}

# LevelDisplayName string → internal severity (used when Level is absent).
_LEVEL_NAME_MAP = {
    "critical": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "verbose": Severity.DEBUG,
}

# Windows PowerShell 5.1 serialises DateTime as "/Date(<ms>[+offset])/".
_DOTNET_DATE_RE = re.compile(r"/Date\((\d+)(?:[+-]\d{4})?\)/")

# Fields lifted into parsed_fields, keyed by their export name.
_PARSED_FIELDS = (
    ("Id", "event_id"),
    ("ProviderName", "provider"),
    ("LogName", "log_name"),
    ("MachineName", "machine"),
    ("RecordId", "record_id"),
    ("Level", "level"),
    ("LevelDisplayName", "level_name"),
    ("Task", "task"),
)


def _parse_ts(value) -> datetime | None:
    """Parse a Windows event timestamp (epoch, /Date(...)/, or ISO 8601)."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # > ~1e11 means milliseconds; smaller is plain seconds.
        seconds = value / 1000 if value > 1e11 else value
        try:
            return datetime.fromtimestamp(seconds, tz=UTC)
        except (ValueError, OSError, OverflowError):
            return None
    if isinstance(value, str):
        m = _DOTNET_DATE_RE.search(value)
        if m:
            try:
                return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=UTC)
            except (ValueError, OSError, OverflowError):
                return None
        token = value.strip().replace("Z", "+00:00")
        token = re.sub(r"(\.\d{6})\d+", r"\1", token)  # microseconds is datetime's limit
        try:
            dt = datetime.fromisoformat(token)
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def _severity(obj: dict) -> Severity:
    level = obj.get("Level")
    if isinstance(level, (int, float)) and not isinstance(level, bool):
        return _LEVEL_MAP.get(int(level), Severity.INFO)
    name = obj.get("LevelDisplayName")
    if isinstance(name, str):
        return _LEVEL_NAME_MAP.get(name.strip().lower(), Severity.INFO)
    return Severity.INFO


def _map_event(obj: dict) -> Event | None:
    """Map one exported Windows event object to an Event."""
    if not isinstance(obj, dict):
        return None

    message = obj.get("Message")
    event_id = obj.get("Id")
    provider = obj.get("ProviderName")
    if message is None:
        if event_id is None:
            return None
        # Some exports omit the rendered text — synthesize a stable message.
        message = f"Event {event_id}" + (f" from {provider}" if provider else "")
    message = str(message)

    parsed = {field: obj[key] for key, field in _PARSED_FIELDS if obj.get(key) is not None}

    return Event(
        raw=message,
        source=str(provider or obj.get("LogName") or "windows"),
        message=message,
        timestamp=_parse_ts(obj.get("TimeCreated")),
        severity=_severity(obj),
        parsed_fields=parsed,
    )


def _parse_payload(text: str) -> list[dict]:
    """Parse an export payload — a JSON object, array, or JSON Lines — to dicts."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fall back to JSON Lines (one compact object per line).
        out: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return [o for o in data if isinstance(o, dict)]
    return []


class WindowsEventLogAdapter(SourceAdapter):
    """Reads Windows events from a JSON export file or live via PowerShell.

    Pass ``path`` to read an exported JSON file, or ``log`` to fetch a live
    log on a Windows host (shelling out to ``Get-WinEvent``). Live mode also
    honours an optional ``provider`` filter.
    """

    def __init__(
        self,
        *,
        path: str | Path | None = None,
        log: str | None = None,
        max_events: int = 200,
        provider: str | None = None,
        powershell: str = "powershell",
        runner=None,
    ) -> None:
        self._path = Path(path) if path else None
        self._log = log
        self._max_events = max_events
        self._provider = provider
        self._powershell = powershell
        self._runner = runner  # live mode, injectable for tests: (list[str]) -> str

        if self._path is None and self._log is None:
            raise ValueError("WindowsEventLogAdapter needs either a JSON 'path' or a 'log' name.")

    # -- payload acquisition -----------------------------------------------

    def _ps_script(self) -> str:
        filt = [f"LogName='{self._log}'"]
        if self._provider:
            filt.append(f"ProviderName='{self._provider}'")
        hashtable = "@{" + "; ".join(filt) + "}"
        fields = (
            "TimeCreated,Id,LevelDisplayName,Level,ProviderName,"
            "LogName,Message,MachineName,RecordId,Task"
        )
        return (
            f"Get-WinEvent -FilterHashtable {hashtable} -MaxEvents {self._max_events} "
            f"-ErrorAction Stop | Select-Object {fields} | ConvertTo-Json -Depth 3"
        )

    def _ps_args(self) -> list[str]:
        return [self._powershell, "-NoProfile", "-NonInteractive", "-Command", self._ps_script()]

    def _run_powershell(self) -> str:
        if self._runner is not None:
            return self._runner(self._ps_args())
        try:
            result = subprocess.run(self._ps_args(), capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError(
                f"{self._powershell} not found — live mode needs PowerShell (use --path instead)."
            )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"Get-WinEvent failed: {detail}")
        return result.stdout

    def _read_payload(self) -> str:
        if self._path is not None:
            if not self._path.exists():
                raise RuntimeError(f"Windows event JSON file not found: {self._path}")
            # Exports often carry a BOM; utf-8-sig strips it transparently.
            return self._path.read_text(encoding="utf-8-sig", errors="replace")
        return self._run_powershell()

    @staticmethod
    def _dedup_key(event: Event):
        rid = event.parsed_fields.get("record_id")
        return rid if rid is not None else (event.timestamp, event.message)

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield every event in the export once (batch mode)."""
        for obj in _parse_payload(self._read_payload()):
            event = _map_event(obj)
            if event is not None:
                yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Re-read the source forever, yielding only newly-arrived events.

        Events are de-duplicated by their Windows RecordId (a monotonically
        increasing per-log counter), so each poll emits only records not seen
        in the previous round. Get-WinEvent returns newest-first, so each
        batch is reversed to deliver events oldest-first like the other
        tailing adapters. Runs until the caller stops iterating.
        """
        seen: set = set()
        first = True
        while True:
            try:
                payload = self._read_payload()
            except RuntimeError:
                if first:
                    raise  # the initial read failed — surface the error
                payload = ""

            events = [e for obj in _parse_payload(payload) if (e := _map_event(obj)) is not None]
            batch_keys = {self._dedup_key(e) for e in events}
            for event in reversed(events):
                key = self._dedup_key(event)
                if key in seen:
                    continue
                yield event
            if batch_keys:
                seen = batch_keys
            first = False
            await asyncio.sleep(interval)
