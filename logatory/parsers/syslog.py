from __future__ import annotations

import re
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import BaseParser

# Matches: "Jan  5 12:34:56 hostname process[pid]: message"
_SYSLOG_RE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)"
)

_AUTH_KEYWORDS = frozenset(
    (
        "sshd",
        "sudo",
        "su",
        "login",
        "passwd",
        "useradd",
        "userdel",
        "groupadd",
        "pam",
        "auth",
    )
)

_MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_timestamp(month: str, day: str, time_str: str) -> datetime | None:
    month_num = _MONTH_MAP.get(month)
    if not month_num:
        return None
    now = datetime.now(tz=UTC)
    year = now.year
    try:
        h, m, s = (int(x) for x in time_str.split(":"))
        return datetime(year, month_num, int(day), h, m, s, tzinfo=UTC)
    except (ValueError, TypeError):
        return None


def _infer_severity(process: str, message: str) -> Severity:
    p = process.lower()
    msg = message.lower()
    if "fail" in msg or "error" in msg or "denied" in msg:
        return Severity.WARNING
    if p in _AUTH_KEYWORDS:
        return Severity.INFO
    return Severity.INFO


class SyslogParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        m = _SYSLOG_RE.match(stripped)
        if not m:
            return None

        fields = m.groupdict()
        timestamp = _parse_timestamp(fields["month"], fields["day"], fields["time"])
        process = fields["process"]
        message = fields["message"]

        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=_infer_severity(process, message),
            parsed_fields={
                "host": fields["host"],
                "process": process,
                "pid": fields.get("pid") or "",
            },
        )


class AuthLogParser(SyslogParser):
    """auth.log uses the same syslog format but focuses on auth processes."""
