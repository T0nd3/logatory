"""logfmt parser — ``key=value`` lines as emitted by many Go services, Heroku
and structured-logging libraries.

A logfmt line is a run of ``key=value`` pairs separated by spaces, where a
value is either a bare token or a double-quoted string (which may contain
spaces and backslash escapes), e.g.::

    level=info ts=2026-06-07T08:15:04Z msg="user logged in" user=bob dur=1.2s

Bare keys/values are kept as strings; the common ``msg``/``level``/``ts``
keys populate the Event's message, severity and timestamp, and every pair is
preserved in ``parsed_fields``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import BaseParser

# key=value  where value is "quoted (with \\ escapes)" or a bare run of
# non-space, non-quote characters (possibly empty, e.g. trailing key=).
_PAIR_RE = re.compile(r'([A-Za-z0-9][\w.\-]*)=(?:"((?:[^"\\]|\\.)*)"|([^\s"]*))')

_SEVERITY_MAP = {
    "debug": Severity.DEBUG,
    "info": Severity.INFO,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "error": Severity.ERROR,
    "err": Severity.ERROR,
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
}

_TS_KEYS = ("ts", "time", "timestamp", "@timestamp", "datetime")
_MSG_KEYS = ("msg", "message", "log", "text")
_SEV_KEYS = ("level", "lvl", "severity", "loglevel", "log_level")

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


def parse_pairs(line: str) -> list[tuple[str, str]]:
    """Tokenize a logfmt line into ordered (key, value) pairs.

    Quoted values are unescaped. Shared with the format detector so detection
    and parsing agree on what counts as a pair.
    """
    pairs: list[tuple[str, str]] = []
    for match in _PAIR_RE.finditer(line):
        key, quoted, bare = match.group(1), match.group(2), match.group(3)
        if quoted is not None:
            value = quoted.replace('\\"', '"').replace("\\\\", "\\")
        else:
            value = bare
        pairs.append((key, value))
    return pairs


def looks_like_logfmt(line: str) -> bool:
    """True when *line* is mostly ``key=value`` pairs (≥2, covering ≥80%).

    The coverage check keeps stray ``x=5`` fragments inside prose from being
    mistaken for structured logfmt output.
    """
    stripped = line.strip()
    if not stripped:
        return False
    covered = 0
    count = 0
    for match in _PAIR_RE.finditer(stripped):
        covered += match.end() - match.start()
        count += 1
    return count >= 2 and covered / len(stripped) >= 0.8


class LogfmtParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        pairs = parse_pairs(stripped)
        if not pairs:
            return None
        fields = dict(pairs)

        message = self._first(fields, _MSG_KEYS) or stripped
        severity = self._severity(fields)
        timestamp = self._timestamp(fields)

        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=severity,
            parsed_fields=fields,
        )

    @staticmethod
    def _first(fields: dict, keys: tuple) -> str | None:
        for key in keys:
            val = fields.get(key)
            if val:
                return val
        return None

    @classmethod
    def _severity(cls, fields: dict) -> Severity:
        raw = cls._first(fields, _SEV_KEYS)
        if raw is None:
            return Severity.INFO
        return _SEVERITY_MAP.get(raw.lower(), Severity.INFO)

    @classmethod
    def _timestamp(cls, fields: dict) -> datetime | None:
        raw = cls._first(fields, _TS_KEYS)
        if raw is None:
            return None
        if raw.isdigit():
            try:
                return datetime.fromtimestamp(int(raw), tz=UTC)
            except (OSError, ValueError, OverflowError):
                return None
        for fmt in _TS_FORMATS:
            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
            except ValueError:
                pass
        return None
