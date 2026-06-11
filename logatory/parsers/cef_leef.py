"""CEF and LEEF parsers — the two dominant security-appliance log formats.

Firewalls, IDS/IPS, WAFs, proxies and SIEM connectors emit events in one of
two pipe-delimited formats:

* **CEF** (Common Event Format, ArcSight)::

      CEF:0|Vendor|Product|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

  Seven ``|``-separated header fields (version, vendor, product, device
  version, signature id, name, severity) followed by a space-separated
  ``key=value`` extension.

* **LEEF** (Log Event Extended Format, IBM QRadar)::

      LEEF:2.0|Vendor|Product|1.0|anomaly|^|src=10.0.0.1^dst=2.1.2.2^sev=5

  Five header fields (version, vendor, product, device version, event id),
  an optional delimiter field in LEEF 2.0, then a delimiter-separated
  ``key=value`` extension (tab by default).

Both formats are frequently wrapped in a syslog prefix; the parsers locate the
``CEF:``/``LEEF:`` marker and ignore anything before it. Header metadata and
every extension pair are preserved in ``parsed_fields``; the human-readable
name (CEF) or ``msg`` (LEEF) becomes the message, and the severity is mapped
onto Logatory's scale.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from ..models import Event, Severity
from .base import BaseParser

# Locate the format marker even when a syslog prefix precedes it.
_CEF_RE = re.compile(r"CEF:\d+\|")
_LEEF_RE = re.compile(r"LEEF:\d+(?:\.\d+)?\|")

# Split on a pipe that is not backslash-escaped.
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")

# CEF extension: key=value, value runs until the next " key=" or end of line.
_CEF_EXT_RE = re.compile(r"(?P<key>[A-Za-z][\w.]*)=(?P<val>.*?)(?=(?:\s+[A-Za-z][\w.]*=)|$)")

_CEF_TIME_KEYS = ("rt", "end", "start", "deviceCustomDate1")
_LEEF_TIME_KEYS = ("devTime", "devtime")
_MSG_KEYS = ("msg", "message")
_SEV_KEYS = ("sev", "severity")

_STRING_SEVERITY = {
    "unknown": Severity.INFO,
    "low": Severity.INFO,
    "medium": Severity.WARNING,
    "high": Severity.ERROR,
    "very-high": Severity.CRITICAL,
    "veryhigh": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
}

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S",
    "%b %d %Y %H:%M:%S",
    "%b %d %H:%M:%S",
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _unescape(value: str, specials: dict[str, str]) -> str:
    """Resolve backslash escapes, mapping known escape chars via *specials*."""
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            out.append(specials.get(nxt, nxt))
            i += 2
        else:
            out.append(char)
            i += 1
    return "".join(out)


def _split_header(body: str, maxsplit: int) -> list[str]:
    return _UNESCAPED_PIPE.split(body, maxsplit=maxsplit)


def _numeric_severity(value: str) -> Severity | None:
    try:
        n = int(value)
    except ValueError:
        return None
    if n <= 3:
        return Severity.INFO
    if n <= 6:
        return Severity.WARNING
    if n <= 8:
        return Severity.ERROR
    return Severity.CRITICAL


def _map_severity(raw: str | None) -> Severity:
    if raw is None:
        return Severity.INFO
    raw = raw.strip()
    numeric = _numeric_severity(raw)
    if numeric is not None:
        return numeric
    return _STRING_SEVERITY.get(raw.lower(), Severity.INFO)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    token = value.strip()
    if not token:
        return None
    if token.isdigit():
        # Epoch — milliseconds if it has 13+ digits, otherwise seconds.
        num = int(token)
        if len(token) >= 12:
            num /= 1000
        try:
            return datetime.fromtimestamp(num, tz=UTC)
        except (OSError, ValueError, OverflowError):
            return None
    iso = token.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(token, fmt)
            if dt.year == 1900:  # formats without a year default to 1900
                dt = dt.replace(year=datetime.now(tz=UTC).year)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def _first(fields: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        val = fields.get(key)
        if val:
            return val
    return None


# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------

_CEF_HEADER_ESCAPES = {"|": "|", "\\": "\\"}
_CEF_VALUE_ESCAPES = {"=": "=", "\\": "\\", "n": "\n", "r": "\r"}


def looks_like_cef(line: str) -> bool:
    return _CEF_RE.search(line) is not None


def _parse_cef_extension(ext: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _CEF_EXT_RE.finditer(ext):
        fields[match.group("key")] = _unescape(match.group("val"), _CEF_VALUE_ESCAPES)
    return fields


def parse_cef(raw: str, source: str) -> Event | None:
    """Parse one CEF line into an Event, or None if it carries no CEF marker."""
    marker = _CEF_RE.search(raw)
    if marker is None:
        return None
    body = raw[marker.start() :].rstrip("\n")

    parts = _split_header(body, maxsplit=7)
    if len(parts) < 7:
        return None
    version = parts[0].split(":", 1)[1]
    vendor, product, dev_version, sig_id, name = (
        _unescape(parts[i], _CEF_HEADER_ESCAPES) for i in range(1, 6)
    )
    severity_raw = parts[6]
    extension = parts[7] if len(parts) > 7 else ""

    fields = _parse_cef_extension(extension)
    metadata = {
        "cef_version": version,
        "cef_vendor": vendor,
        "cef_product": product,
        "cef_device_version": dev_version,
        "cef_signature_id": sig_id,
        "cef_name": name,
        "cef_severity": severity_raw,
    }
    # Extension values win over header metadata on key collisions.
    parsed_fields = {**metadata, **fields}

    message = name or _first(fields, _MSG_KEYS) or body
    severity = _map_severity(severity_raw)
    timestamp = _parse_time(_first(fields, _CEF_TIME_KEYS))

    return Event(
        raw=raw.rstrip("\n"),
        source=source,
        message=message,
        timestamp=timestamp,
        severity=severity,
        parsed_fields=parsed_fields,
    )


class CEFParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        if not line.strip():
            return None
        return parse_cef(line, self.source)


# ---------------------------------------------------------------------------
# LEEF
# ---------------------------------------------------------------------------

_LEEF_VALUE_ESCAPES = {"\\": "\\", "n": "\n", "r": "\r", "t": "\t"}


def looks_like_leef(line: str) -> bool:
    return _LEEF_RE.search(line) is not None


def _resolve_delimiter(spec: str) -> str:
    spec = spec.strip()
    if not spec:
        return "\t"
    if spec in (r"\t", "\\t"):
        return "\t"
    match = re.fullmatch(r"(?:0x|x)([0-9a-fA-F]{1,2})", spec)
    if match:
        return chr(int(match.group(1), 16))
    if len(spec) == 1:
        return spec
    return "\t"


def _parse_leef_extension(ext: str, delimiter: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for chunk in ext.split(delimiter):
        if "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        key = key.strip()
        if key:
            fields[key] = _unescape(value, _LEEF_VALUE_ESCAPES)
    return fields


def parse_leef(raw: str, source: str) -> Event | None:
    """Parse one LEEF line into an Event, or None if it carries no marker."""
    marker = _LEEF_RE.search(raw)
    if marker is None:
        return None
    body = raw[marker.start() :].rstrip("\n")

    parts = _split_header(body, maxsplit=6)
    if len(parts) < 5:
        return None
    version = parts[0].split(":", 1)[1]
    vendor, product, dev_version, event_id = parts[1], parts[2], parts[3], parts[4]

    # LEEF 2.0 may carry a custom delimiter as the sixth header field; LEEF 1.0
    # always uses a tab. We treat the sixth field as a delimiter only when it
    # parses as one and a seventh (extension) field follows it.
    delimiter = "\t"
    extension = parts[5] if len(parts) > 5 else ""
    if version.startswith("2") and len(parts) > 6:
        delimiter = _resolve_delimiter(parts[5])
        extension = parts[6]

    fields = _parse_leef_extension(extension, delimiter)
    metadata = {
        "leef_version": version,
        "leef_vendor": vendor,
        "leef_product": product,
        "leef_device_version": dev_version,
        "leef_event_id": event_id,
    }
    parsed_fields = {**metadata, **fields}

    message = _first(fields, _MSG_KEYS) or event_id or body
    severity = _map_severity(_first(fields, _SEV_KEYS))
    timestamp = _parse_time(_first(fields, _LEEF_TIME_KEYS))

    return Event(
        raw=raw.rstrip("\n"),
        source=source,
        message=message,
        timestamp=timestamp,
        severity=severity,
        parsed_fields=parsed_fields,
    )


class LEEFParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        if not line.strip():
            return None
        return parse_leef(line, self.source)
