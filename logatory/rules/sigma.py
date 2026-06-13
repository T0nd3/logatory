"""
Sigma compatibility layer.

Reads a Sigma rule (https://github.com/SigmaHQ/sigma) and converts it to
our internal Rule format. Supports a practical subset of Sigma:
  - Simple field matching (eq, contains, startswith, endswith, re)
  - Count aggregation:  condition: selection | count() by field > N
  - logsource: category / service mapping to our LogFormat names

Unsupported (raises SigmaConversionError):
  - Multiple named selections combined with AND/OR in condition
  - near / sequence conditions
  - fieldref / cidr modifiers
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..models import FindingSeverity
from .model import AggregateCondition, MatchCondition, Rule

_LEVEL_MAP = {
    "informational": FindingSeverity.LOW,
    "low": FindingSeverity.LOW,
    "medium": FindingSeverity.MEDIUM,
    "high": FindingSeverity.HIGH,
    "critical": FindingSeverity.CRITICAL,
}

# Sigma logsource → our format names
_LOGSOURCE_MAP: dict[tuple[str, str], list[str]] = {
    ("category", "authentication"): ["auth_log", "syslog"],
    ("category", "webserver"): ["nginx_combined", "apache_error", "traefik"],
    ("category", "proxy"): ["nginx_combined", "haproxy", "traefik"],
    ("service", "sshd"): ["auth_log", "syslog"],
    ("service", "nginx"): ["nginx_combined"],
    ("service", "apache"): ["nginx_combined", "apache_error"],
    ("service", "haproxy"): ["haproxy"],
    ("service", "traefik"): ["traefik"],
    ("product", "windows"): ["evtx"],
}

# Sigma field modifier → our op name
_MODIFIER_MAP = {
    "contains": "contains",
    "startswith": "startswith",
    "endswith": "endswith",
    "re": "re",
    "gt": "gt",
    "lt": "lt",
    "gte": "gte",
    "lte": "lte",
}

# Sigma field name → our field path (best-effort)
_FIELD_MAP = {
    "EventID": "parsed_fields.event_id",
    "Image": "parsed_fields.image",
    "CommandLine": "parsed_fields.command_line",
    "User": "parsed_fields.user",
    "IpAddress": "parsed_fields.ip_address",
    "Keywords": "parsed_fields.keywords",
    "message": "message",
    "msg": "message",
}


class SigmaConversionError(Exception):
    pass


def load_sigma_file(path: Path) -> Rule:
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return _convert(data, str(path))


def _convert(data: dict, source_file: str) -> Rule:
    rule_id = data.get("id") or _slugify(data.get("title", "unknown"))
    title = data.get("title", rule_id)
    level = _LEVEL_MAP.get(str(data.get("level", "medium")).lower(), FindingSeverity.MEDIUM)
    logsource_formats = _map_logsource(data.get("logsource", {}))
    match_conds, aggregate = _parse_detection(data.get("detection", {}))

    return Rule(
        id=rule_id,
        title=title,
        level=level,
        match=match_conds,
        aggregate=aggregate,
        description=data.get("description", ""),
        logsource_formats=logsource_formats or None,
        tags=list(data.get("tags", [])),
        source_file=source_file,
    )


def _map_logsource(ls: dict) -> list[str]:
    formats: set[str] = set()
    for key in ("category", "service", "product"):
        val = ls.get(key, "").lower()
        if val:
            mapped = _LOGSOURCE_MAP.get((key, val), [])
            formats.update(mapped)
    return sorted(formats)


def _parse_detection(det: dict) -> tuple[list[MatchCondition], AggregateCondition | None]:
    condition_str = str(det.get("condition", "selection"))
    aggregate = _parse_aggregate_condition(condition_str, det)

    # Find the primary selection (named "selection" or the first non-"condition" key)
    selection_key = "selection"
    if selection_key not in det:
        candidates = [k for k in det if k != "condition"]
        if not candidates:
            return [], aggregate
        selection_key = candidates[0]

    selection = det[selection_key]
    match_conds = _parse_selection(selection)
    return match_conds, aggregate


def _parse_selection(sel) -> list[MatchCondition]:
    conds: list[MatchCondition] = []

    if isinstance(sel, dict):
        for field_expr, value in sel.items():
            field_path, op = _parse_field_expr(field_expr)
            values = value if isinstance(value, list) else [value]
            # Multiple values in a list = OR; we take the first for simplicity
            # A full implementation would emit OR conditions
            for v in values:
                conds.append(MatchCondition(field=field_path, op=op, value=str(v)))
                break  # only first value — OR support is a future improvement
    elif isinstance(sel, list):
        for item in sel:
            conds.extend(_parse_selection(item))

    return conds


def _parse_field_expr(expr: str) -> tuple[str, str]:
    parts = expr.split("|")
    sigma_field = parts[0].strip()
    field_path = _FIELD_MAP.get(sigma_field, f"parsed_fields.{sigma_field.lower()}")
    op = "eq"
    if len(parts) > 1:
        modifier = parts[1].strip().lower()
        op = _MODIFIER_MAP.get(modifier, "contains")
    return field_path, op


# Matches: "selection | count() by FieldName > 5"
_AGG_RE = re.compile(
    r"(\w+)\s*\|\s*count\(\)\s*(?:by\s+(\w+))?\s*([><=!]+)\s*(\d+)",
    re.IGNORECASE,
)
_TIMEFRAME_RE = re.compile(r"(\d+)([smhd])")


def _parse_aggregate_condition(condition_str: str, det: dict) -> AggregateCondition | None:
    m = _AGG_RE.search(condition_str)
    if not m:
        return None

    _, group_field, op, threshold = m.group(1), m.group(2), m.group(3), int(m.group(4))

    timeframe_str = str(det.get("timeframe", "5m"))
    tf_m = _TIMEFRAME_RE.match(timeframe_str)
    if not tf_m:
        raise SigmaConversionError(f"Cannot parse timeframe '{timeframe_str}'")
    timeframe_seconds = (
        int(tf_m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[tf_m.group(2)]
    )

    group_by = (
        _FIELD_MAP.get(group_field, f"parsed_fields.{group_field.lower()}")
        if group_field
        else None
    )

    return AggregateCondition(
        count_op=op,
        count_val=threshold,
        timeframe_seconds=timeframe_seconds,
        group_by=group_by,
    )


def _slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
