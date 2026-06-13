from __future__ import annotations

from pathlib import Path

import yaml

from ..models import FindingSeverity
from . import BUILTIN_RULES_DIR
from .engine import RuleEngine
from .model import AggregateCondition, MatchCondition, Rule

_LEVEL_MAP = {
    "low": FindingSeverity.LOW,
    "medium": FindingSeverity.MEDIUM,
    "high": FindingSeverity.HIGH,
    "critical": FindingSeverity.CRITICAL,
}

_TIMEFRAME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_timeframe(s: str) -> int:
    unit = s[-1]
    if unit not in _TIMEFRAME_UNITS:
        raise ValueError(f"Unknown timeframe unit '{unit}' in '{s}'. Use s/m/h/d.")
    return int(s[:-1]) * _TIMEFRAME_UNITS[unit]


def _parse_count_expr(expr: str) -> tuple[str, int]:
    for op in (">=", "<=", "!=", ">", "<", "=="):
        if expr.lstrip().startswith(op):
            return op, int(expr.lstrip()[len(op) :].strip())
    return ">=", int(expr.strip())


def _load_one(data: dict, source_file: str) -> Rule:
    rule_id = data.get("id") or ""
    if not rule_id:
        raise ValueError(f"Rule in {source_file} is missing 'id'")
    title = data.get("title") or rule_id
    level_str = str(data.get("level", "medium")).lower()
    level = _LEVEL_MAP.get(level_str, FindingSeverity.MEDIUM)

    raw_formats = data.get("logsource", {}).get("formats")
    logsource_formats = list(raw_formats) if raw_formats else None

    match_conditions: list[MatchCondition] = [
        MatchCondition(
            field=cond["field"],
            op=cond.get("op", "eq"),
            value=str(cond["value"]),
        )
        for cond in data.get("detection", {}).get("match", [])
    ]

    aggregate: AggregateCondition | None = None
    agg_data = data.get("detection", {}).get("aggregate")
    if agg_data:
        count_op, count_val = _parse_count_expr(str(agg_data["count"]))
        aggregate = AggregateCondition(
            count_op=count_op,
            count_val=count_val,
            timeframe_seconds=_parse_timeframe(str(agg_data["timeframe"])),
            group_by=agg_data.get("group_by"),
            group_by_regex=agg_data.get("group_by_regex"),
        )

    return Rule(
        id=rule_id,
        title=title,
        level=level,
        match=match_conditions,
        aggregate=aggregate,
        description=data.get("description", ""),
        logsource_formats=logsource_formats,
        tags=list(data.get("tags", [])),
        source_file=source_file,
    )


def rule_from_dict(data: dict, source_file: str = "<dict>") -> Rule:
    """Create a Rule directly from a Python dict (same schema as YAML rule files)."""
    return _load_one(data, source_file)


def load_rule_file(path: Path) -> Rule:
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return _load_one(data, str(path))


def load_rules_dir(directory: Path) -> list[Rule]:
    rules = []
    for path in sorted(directory.glob("*.yml")):
        try:
            rules.append(load_rule_file(path))
        except Exception as e:
            raise ValueError(f"Failed to load rule {path}: {e}") from e
    return rules


def validate_rule_file(path: Path) -> list[str]:
    """Return a list of validation errors (empty = valid)."""
    errors: list[str] = []
    try:
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if not data.get("id"):
        errors.append("Missing required field: 'id'")
    if not data.get("title"):
        errors.append("Missing required field: 'title'")
    if data.get("level") and data["level"] not in _LEVEL_MAP:
        errors.append(f"Invalid level '{data['level']}'. Use: low/medium/high/critical")

    for i, cond in enumerate(data.get("detection", {}).get("match", [])):
        if "field" not in cond:
            errors.append(f"match[{i}]: missing 'field'")
        if "value" not in cond:
            errors.append(f"match[{i}]: missing 'value'")
        valid_ops = {
            "eq",
            "ne",
            "contains",
            "startswith",
            "endswith",
            "re",
            "gt",
            "lt",
            "gte",
            "lte",
        }
        op = cond.get("op", "eq")
        if op not in valid_ops:
            errors.append(f"match[{i}]: unknown op '{op}'. Valid: {', '.join(sorted(valid_ops))}")

    agg = data.get("detection", {}).get("aggregate")
    if agg:
        if "count" not in agg:
            errors.append("aggregate: missing 'count'")
        if "timeframe" not in agg:
            errors.append("aggregate: missing 'timeframe'")
        else:
            tf = str(agg["timeframe"])
            if not tf or tf[-1] not in _TIMEFRAME_UNITS:
                errors.append(f"aggregate: invalid timeframe '{tf}'. Use e.g. 30s, 5m, 1h")

    return errors


def build_engine(
    no_rules: bool,
    rules_dir: Path | None,
    plugin_registry,
) -> RuleEngine | None:
    """Construct a :class:`RuleEngine` from the standard rule sources.

    Combines, in order:

    * the shipped built-in rules under ``BUILTIN_RULES_DIR``
    * an optional CLI-supplied ``--rules-dir``
    * any directories the plugin registry exposes via ``rule_dirs``
    * any in-memory rules the plugin registry exposes via ``rules``

    Returns ``None`` when *no_rules* is True — every CLI command uses
    that to honour ``--no-rules``.

    ``plugin_registry`` is duck-typed: anything with ``rule_dirs`` and
    ``rules`` attributes works.  This keeps the rules package free of
    an import dependency on the plugins package.
    """
    if no_rules:
        return None
    all_rules = list(load_rules_dir(BUILTIN_RULES_DIR))
    if rules_dir and rules_dir.is_dir():
        all_rules.extend(load_rules_dir(rules_dir))
    for pdir in plugin_registry.rule_dirs:
        all_rules.extend(load_rules_dir(pdir))
    all_rules.extend(plugin_registry.rules)
    return RuleEngine(all_rules)
