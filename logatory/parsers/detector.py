from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

from .logfmt import looks_like_logfmt


class LogFormat(str, Enum):
    JSON_LINES = "json_lines"
    NGINX_COMBINED = "nginx_combined"
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    LOGFMT = "logfmt"
    PLAINTEXT = "plaintext"


_NGINX_RE = re.compile(r'^\S+ \S+ \S+ \[.+\] "[A-Z]+ .+ HTTP/\d\.\d" \d{3} \d+')
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \S+(\[\d+\])?:")
_AUTH_LOG_RE = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ (sshd|sudo|su|login|passwd)\b")


class FormatDetector:
    def detect(self, sample_lines: list[str], path: Path | None = None) -> LogFormat:
        non_empty = [line.strip() for line in sample_lines if line.strip()]
        if not non_empty:
            return LogFormat.PLAINTEXT

        json_hits = sum(1 for line in non_empty if self._is_json(line))
        if json_hits / len(non_empty) >= 0.8:
            return LogFormat.JSON_LINES

        auth_hits = sum(1 for line in non_empty if _AUTH_LOG_RE.match(line))
        if auth_hits / len(non_empty) >= 0.6:
            return LogFormat.AUTH_LOG

        nginx_hits = sum(1 for line in non_empty if _NGINX_RE.match(line))
        if nginx_hits / len(non_empty) >= 0.6:
            return LogFormat.NGINX_COMBINED

        syslog_hits = sum(1 for line in non_empty if _SYSLOG_RE.match(line))
        if syslog_hits / len(non_empty) >= 0.6:
            return LogFormat.SYSLOG

        logfmt_hits = sum(1 for line in non_empty if looks_like_logfmt(line))
        if logfmt_hits / len(non_empty) >= 0.8:
            return LogFormat.LOGFMT

        return LogFormat.PLAINTEXT

    @staticmethod
    def _is_json(line: str) -> bool:
        try:
            obj = json.loads(line)
            return isinstance(obj, dict)
        except (json.JSONDecodeError, ValueError):
            return False
