from __future__ import annotations

import json
import re
from enum import Enum
from pathlib import Path

from .cef_leef import looks_like_cef, looks_like_leef
from .logfmt import looks_like_logfmt
from .plugins import plugin_parsers


class LogFormat(str, Enum):
    JSON_LINES = "json_lines"
    NGINX_COMBINED = "nginx_combined"
    APACHE_ERROR = "apache_error"
    HAPROXY = "haproxy"
    SYSLOG = "syslog"
    AUTH_LOG = "auth_log"
    LOGFMT = "logfmt"
    CEF = "cef"
    LEEF = "leef"
    PLAINTEXT = "plaintext"


_NGINX_RE = re.compile(r'^\S+ \S+ \S+ \[.+\] "[A-Z]+ .+ HTTP/\d\.\d" \d{3} \d+')
_APACHE_ERROR_RE = re.compile(r"^\[[^\]]+\] \[(?:\w+:)?\w+\] ")
_HAPROXY_RE = re.compile(r"\S+:\d+ \[\d{2}/\w{3}/\d{4}:[\d:]+\.\d+\] \S+ \S+/\S+ [\d/+-]+ \d{3} ")
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ \S+(\[\d+\])?:")
_AUTH_LOG_RE = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ (sshd|sudo|su|login|passwd)\b")


class FormatDetector:
    def detect(self, sample_lines: list[str], path: Path | None = None) -> LogFormat | str:
        non_empty = [line.strip() for line in sample_lines if line.strip()]
        if not non_empty:
            return LogFormat.PLAINTEXT

        json_hits = sum(1 for line in non_empty if self._is_json(line))
        if json_hits / len(non_empty) >= 0.8:
            return LogFormat.JSON_LINES

        # CEF/LEEF carry a distinctive marker and are often wrapped in a syslog
        # prefix, so they must be checked before the syslog rule below.
        cef_hits = sum(1 for line in non_empty if looks_like_cef(line))
        if cef_hits / len(non_empty) >= 0.6:
            return LogFormat.CEF

        leef_hits = sum(1 for line in non_empty if looks_like_leef(line))
        if leef_hits / len(non_empty) >= 0.6:
            return LogFormat.LEEF

        # HAProxy is usually wrapped in a syslog prefix, so it must be checked
        # before the syslog/auth rules below; .search skips any such prefix.
        haproxy_hits = sum(1 for line in non_empty if _HAPROXY_RE.search(line))
        if haproxy_hits / len(non_empty) >= 0.6:
            return LogFormat.HAPROXY

        apache_error_hits = sum(1 for line in non_empty if _APACHE_ERROR_RE.match(line))
        if apache_error_hits / len(non_empty) >= 0.6:
            return LogFormat.APACHE_ERROR

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

        # Plugin-registered parsers get a chance before the plaintext fallback;
        # the first whose detect() accepts the sample wins, identified by name.
        for plugin in plugin_parsers():
            if plugin.detect(non_empty):
                return plugin.name

        return LogFormat.PLAINTEXT

    @staticmethod
    def _is_json(line: str) -> bool:
        try:
            obj = json.loads(line)
            return isinstance(obj, dict)
        except (json.JSONDecodeError, ValueError):
            return False
