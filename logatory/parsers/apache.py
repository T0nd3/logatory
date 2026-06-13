from __future__ import annotations

import re
from datetime import datetime

from ..models import Event, Severity
from .base import BaseParser

# Apache error log. Handles both the classic 2.2 layout and the 2.4 layout:
#   [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] File does not exist
#   [Wed Oct 11 14:32:52.123456 2000] [core:error] [pid 12345:tid 140] \
#       [client 1.2.3.4:56] AH00128: File does not exist
_ERROR_RE = re.compile(
    r"^\[(?P<time>[^\]]+)\] "
    r"\[(?:(?P<module>[^\]:]+):)?(?P<level>\w+)\] "
    r"(?:\[pid (?P<pid>\d+)(?::tid \d+)?\] )?"
    r"(?:\[client (?P<client>[^\]]+)\] )?"
    r"(?P<message>.*)$"
)

_LEVEL_MAP = {
    "emerg": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "error": Severity.ERROR,
    "err": Severity.ERROR,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "notice": Severity.INFO,
    "info": Severity.INFO,
    "debug": Severity.DEBUG,
    "trace1": Severity.DEBUG,
}


def _parse_time(raw: str) -> datetime | None:
    # Apache 2.4 adds fractional seconds; strptime's %a/%b are locale-sensitive,
    # so drop the sub-second part and parse the stable remainder.
    cleaned = re.sub(r"\.\d+", "", raw)
    try:
        return datetime.strptime(cleaned, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


class ApacheErrorParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        m = _ERROR_RE.match(stripped)
        if not m:
            return None

        fields = m.groupdict()
        level = (fields["level"] or "").lower()

        return Event(
            raw=stripped,
            source=self.source,
            message=fields["message"],
            timestamp=_parse_time(fields["time"]),
            severity=_LEVEL_MAP.get(level, Severity.INFO),
            parsed_fields={
                "level": level,
                "module": fields.get("module") or "",
                "pid": fields.get("pid") or "",
                "client": fields.get("client") or "",
            },
        )
