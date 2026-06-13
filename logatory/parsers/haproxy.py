from __future__ import annotations

import re
from datetime import datetime

from ..models import Event, Severity
from .base import BaseParser

# HAProxy HTTP log. Lines are usually delivered through syslog, so an optional
# "<...> haproxy[pid]: " prefix is stripped before matching the HAProxy payload.
#
# Payload field order:
#   client_ip:port [accept_date] frontend backend/server Tq/Tw/Tc/Tr/Tt \
#       status bytes req_cookie resp_cookie term_state \
#       actconn/feconn/beconn/srvconn/retries srv_queue/backend_queue "request"
_PREFIX_RE = re.compile(r"^.*?haproxy\[\d+\]:\s*")

_HTTP_RE = re.compile(
    r"^(?P<client_ip>\S+):(?P<client_port>\d+) "
    r"\[(?P<accept_date>[^\]]+)\] "
    r"(?P<frontend>\S+) "
    r"(?P<backend>[^/\s]+)/(?P<server>\S+) "
    r"(?P<timers>[\d/+-]+) "
    r"(?P<status>\d{3}) "
    r"(?P<bytes>\d+) "
    r"\S+ \S+ "
    r"(?P<term_state>\S+) "
    r"(?P<conns>[\d/]+) "
    r"(?P<queues>[\d/]+) "
    r'"(?P<request>[^"]*)"'
)

_TIME_FMT = "%d/%b/%Y:%H:%M:%S.%f"


def _status_to_severity(status: int) -> Severity:
    if status >= 500:
        return Severity.ERROR
    if status >= 400:
        return Severity.WARNING
    return Severity.INFO


class HAProxyParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped:
            return None
        payload = _PREFIX_RE.sub("", stripped)
        m = _HTTP_RE.match(payload)
        if not m:
            return None

        fields = m.groupdict()
        status = int(fields["status"])
        try:
            timestamp = datetime.strptime(fields["accept_date"], _TIME_FMT)
        except ValueError:
            timestamp = None

        message = f"{fields['request']} -> {status}"

        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=_status_to_severity(status),
            parsed_fields={
                "client_ip": fields["client_ip"],
                "frontend": fields["frontend"],
                "backend": fields["backend"],
                "server": fields["server"],
                "status": status,
                "bytes": fields["bytes"],
                "request": fields["request"],
                "term_state": fields["term_state"],
                "timers": fields["timers"],
            },
        )
