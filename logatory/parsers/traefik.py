from __future__ import annotations

import re
from datetime import datetime

from ..models import Event, Severity
from .base import BaseParser

# Traefik access log in its "common" format. This is an *extended* Common Log
# Format: the leading part is identical to nginx/Apache combined logs, but
# Traefik appends four signature fields that disambiguate it:
#
#   <count> "<router>" "<server_url>" <duration>ms
#
# Example:
#   192.168.1.20 - jdoe [13/Jun/2026:08:15:04 +0000] "GET /api HTTP/1.1" \
#       200 1234 "https://ex.com" "Mozilla/5.0" 42 "users@docker" \
#       "http://172.17.0.3:80" 12ms
#
# Traefik's JSON access logs are valid JSON and are handled by the json_lines
# parser instead — this parser targets only the common/CLF format.
_CLF_RE = re.compile(
    r"^(?P<client_ip>\S+) \S+ (?P<user>\S+) "
    r"\[(?P<ts>[^\]]+)\] "
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<proto>HTTP/\d\.\d)" '
    r"(?P<status>\d{3}) (?P<size>\S+) "
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)" '
    r'(?P<reqcount>\d+) "(?P<router>[^"]*)" "(?P<server>[^"]*)" '
    r"(?P<duration>\d+)ms"
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _status_to_severity(status: int) -> Severity:
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.WARNING
    return Severity.INFO


class TraefikParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        m = _CLF_RE.match(stripped)
        if not m:
            return None

        fields = m.groupdict()
        status = int(fields["status"])
        try:
            timestamp = datetime.strptime(fields["ts"], _TIME_FMT)
        except ValueError:
            timestamp = None

        message = f"{fields['method']} {fields['path']} -> {status}"

        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=_status_to_severity(status),
            parsed_fields={
                "client_ip": fields["client_ip"],
                "user": fields["user"],
                "method": fields["method"],
                "path": fields["path"],
                "proto": fields["proto"],
                "status": status,
                "size": fields["size"],
                "referer": fields["referer"],
                "user_agent": fields["ua"],
                "router": fields["router"],
                "server": fields["server"],
                "duration_ms": int(fields["duration"]),
            },
        )
