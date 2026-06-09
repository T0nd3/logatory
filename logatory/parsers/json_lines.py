from __future__ import annotations

import json
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import BaseParser

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

_TS_FIELDS = ("timestamp", "time", "ts", "@timestamp", "datetime")
_MSG_FIELDS = ("message", "msg", "log", "text", "body")
_SEV_FIELDS = ("level", "severity", "loglevel", "log_level")


class JsonLinesParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        try:
            obj = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(obj, dict):
            return None

        timestamp = self._extract_timestamp(obj)
        message = self._extract_str(obj, _MSG_FIELDS) or stripped
        severity = self._extract_severity(obj)

        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=severity,
            parsed_fields=dict(obj.items()),
        )

    @staticmethod
    def _extract_timestamp(obj: dict) -> datetime | None:
        for key in _TS_FIELDS:
            val = obj.get(key)
            if not val:
                continue
            if isinstance(val, (int, float)):
                try:
                    return datetime.fromtimestamp(val, tz=UTC)
                except (OSError, ValueError, OverflowError):
                    pass
            if isinstance(val, str):
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S.%f",
                    "%Y-%m-%d %H:%M:%S",
                ):
                    try:
                        return datetime.strptime(val, fmt).replace(tzinfo=UTC)
                    except ValueError:
                        pass
        return None

    @staticmethod
    def _extract_str(obj: dict, fields: tuple) -> str | None:
        for key in fields:
            val = obj.get(key)
            if isinstance(val, str) and val:
                return val
        return None

    @staticmethod
    def _extract_severity(obj: dict) -> Severity:
        for key in _SEV_FIELDS:
            val = obj.get(key)
            if isinstance(val, str):
                return _SEVERITY_MAP.get(val.lower(), Severity.INFO)
        return Severity.INFO
