"""Read-only investigation tools the agent can call against the local database.

Every tool returns a JSON string (the model reads JSON well) and is strictly
read-only with bounded result sizes, so an agent run can never mutate state or
blow up the context window.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ..storage.baseline_repo import BaselineRepository
from ..storage.errors_repo import ErrorsRepository
from ..storage.findings_repo import FindingsRepository
from .agent import Tool
from .tools import ToolSpec

# Keep tool output bounded so the model context stays manageable.
_MAX_LIMIT = 10
_MAX_STACK_CHARS = 2500
_MAX_SAMPLE_CHARS = 300


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}  # noqa: SIM118 — Row iter yields values, not keys


def _clamp(limit: Any, default: int = 5) -> int:
    try:
        n = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, _MAX_LIMIT))


def _clamp_window(value: Any, default: int, hi: int) -> int:
    """Clamp a days/hours window argument to a sane bounded range."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(1, min(n, hi))


def _error_summary_row(r: sqlite3.Row) -> dict[str, Any]:
    return {
        "fingerprint": r["fingerprint"],
        "error_type": r["error_type"],
        "severity": r["severity"],
        "count": r["count"],
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
    }


def _dumps(obj: Any) -> str:
    return json.dumps(obj, default=str, ensure_ascii=False)


def build_investigation_tools(db_path: Path) -> list[Tool]:
    """Build the read-only DB toolset bound to *db_path*."""

    def get_error(fingerprint: str) -> str:
        with ErrorsRepository(db_path) as repo:
            row = repo.get_error(fingerprint)
        if not row:
            return _dumps({"error": f"No tracked error with fingerprint '{fingerprint}'."})
        return _dumps(_row_to_dict(row))

    def get_occurrences(fingerprint: str, limit: int = 5) -> str:
        n = _clamp(limit)
        with ErrorsRepository(db_path) as repo:
            rows = repo.get_occurrences(fingerprint, limit=n)
        out = []
        for r in rows:
            d = _row_to_dict(r)
            if d.get("stack_trace"):
                d["stack_trace"] = d["stack_trace"][:_MAX_STACK_CHARS]
            if d.get("sample"):
                d["sample"] = d["sample"][:_MAX_SAMPLE_CHARS]
            out.append(d)
        return _dumps(out)

    def list_errors(severity: str = "", sort: str = "count", limit: int = 10) -> str:
        n = _clamp(limit, default=10)
        with ErrorsRepository(db_path) as repo:
            rows = repo.list_errors(sort=sort or "count", severity=severity or None, limit=n)
        out = [
            {
                "fingerprint": r["fingerprint"],
                "error_type": r["error_type"],
                "severity": r["severity"],
                "count": r["count"],
                "last_seen": r["last_seen"],
                "normalized_msg": (r["normalized_msg"] or "")[:_MAX_SAMPLE_CHARS],
            }
            for r in rows
        ]
        return _dumps(out)

    def search_findings(keyword: str, limit: int = 10) -> str:
        n = _clamp(limit, default=10)
        if not db_path.exists() or not keyword:
            return _dumps([])
        pattern = f"%{keyword}%"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            try:
                rows = conn.execute(
                    """
                    SELECT rule_id, severity, message, source, created_at
                      FROM findings
                     WHERE message LIKE ? OR rule_id LIKE ?
                     ORDER BY created_at DESC
                     LIMIT ?
                    """,
                    (pattern, pattern, n),
                ).fetchall()
            except sqlite3.OperationalError:
                return _dumps([])  # findings table not created yet
        finally:
            conn.close()
        return _dumps([_row_to_dict(r) for r in rows])

    def get_summary() -> str:
        with ErrorsRepository(db_path) as repo:
            errors = repo.summary()
        with FindingsRepository(db_path) as frepo:
            findings = frepo.summary()
        return _dumps({"errors": errors, "findings": findings})

    def list_regressions(gap_hours: int = 24) -> str:
        gap = _clamp_window(gap_hours, default=24, hi=720)
        with ErrorsRepository(db_path) as repo:
            rows = repo.regression_errors(gap_hours=gap)
        return _dumps([_error_summary_row(r) for r in rows[:_MAX_LIMIT]])

    def error_trend(days: int = 14) -> str:
        d = _clamp_window(days, default=14, hi=90)
        with ErrorsRepository(db_path) as repo:
            rows = repo.daily_occurrences(days=d)
        return _dumps(rows)

    def top_finding_rules(sort: str = "count", limit: int = 10) -> str:
        n = _clamp(limit, default=10)
        with FindingsRepository(db_path) as frepo:
            rows = frepo.count_by_rule(limit=n, sort=sort or "count")
        return _dumps([_row_to_dict(r) for r in rows])

    def get_findings_by_rule(rule_id: str, limit: int = 5) -> str:
        n = _clamp(limit)
        with FindingsRepository(db_path) as frepo:
            rows = frepo.get_by_rule(rule_id, limit=n)
        out = []
        for r in rows:
            d = _row_to_dict(r)
            if d.get("raw_event"):
                d["raw_event"] = d["raw_event"][:_MAX_SAMPLE_CHARS]
            out.append(d)
        return _dumps(out)

    def list_anomaly_sources() -> str:
        with BaselineRepository(db_path) as repo:
            rows = repo.list_sources()
        return _dumps(rows[:_MAX_LIMIT])

    def get_baseline(source: str) -> str:
        with BaselineRepository(db_path) as repo:
            stats = repo.get_stats(source)
        if stats is None:
            return _dumps({"error": f"No trained baseline for source '{source}'."})
        return _dumps(
            {
                "source_key": stats.source_key,
                "n_buckets": stats.n_buckets,
                "trained": stats.is_trained(),
                "features": {
                    name: {"mean": round(fs.mean, 4), "std": round(fs.std, 4), "n": fs.n}
                    for name, fs in stats.features.items()
                },
            }
        )

    return [
        Tool(
            spec=ToolSpec(
                name="get_error",
                description="Fetch a tracked error record by its fingerprint "
                "(type, severity, count, first/last seen, normalized message).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "fingerprint": {
                            "type": "string",
                            "description": "The error fingerprint to look up.",
                        }
                    },
                    "required": ["fingerprint"],
                },
            ),
            handler=get_error,
        ),
        Tool(
            spec=ToolSpec(
                name="get_occurrences",
                description="Fetch recent occurrences of an error, including stack "
                "traces and raw log samples — the richest evidence for root cause.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "fingerprint": {"type": "string", "description": "The error fingerprint."},
                        "limit": {
                            "type": "integer",
                            "description": "How many recent occurrences (max 10).",
                        },
                    },
                    "required": ["fingerprint"],
                },
            ),
            handler=get_occurrences,
        ),
        Tool(
            spec=ToolSpec(
                name="list_errors",
                description="List tracked errors, optionally filtered by severity, "
                "to find related or co-occurring problems.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "severity": {
                            "type": "string",
                            "description": "Filter: debug|info|warning|error|critical (optional).",
                        },
                        "sort": {
                            "type": "string",
                            "description": "Sort key: count|last_seen|first_seen.",
                        },
                        "limit": {"type": "integer", "description": "Max rows (max 10)."},
                    },
                    "required": [],
                },
            ),
            handler=list_errors,
        ),
        Tool(
            spec=ToolSpec(
                name="search_findings",
                description="Search persisted rule/anomaly findings whose message or "
                "rule id contains a keyword.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "keyword": {"type": "string", "description": "Substring to search for."},
                        "limit": {"type": "integer", "description": "Max rows (max 10)."},
                    },
                    "required": ["keyword"],
                },
            ),
            handler=search_findings,
        ),
        Tool(
            spec=ToolSpec(
                name="get_summary",
                description="High-level overview of the whole dataset: error-type and "
                "occurrence totals plus severity breakdowns for errors and findings. "
                "A good first call to orient an investigation.",
                input_schema={"type": "object", "properties": {}, "required": []},
            ),
            handler=get_summary,
        ),
        Tool(
            spec=ToolSpec(
                name="list_regressions",
                description="List errors that went quiet and then reappeared (likely "
                "regressions) — old first_seen but a recent last_seen.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "gap_hours": {
                            "type": "integer",
                            "description": "Silence window in hours (default 24, max 720).",
                        }
                    },
                    "required": [],
                },
            ),
            handler=list_regressions,
        ),
        Tool(
            spec=ToolSpec(
                name="error_trend",
                description="Daily error-occurrence counts over the last N days, to judge "
                "whether overall error volume is rising, falling or spiking.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "days": {
                            "type": "integer",
                            "description": "How many days back (default 14, max 90).",
                        }
                    },
                    "required": [],
                },
            ),
            handler=error_trend,
        ),
        Tool(
            spec=ToolSpec(
                name="top_finding_rules",
                description="The rules that fire most often (or most severely). Use to see "
                "which detections dominate. sort=count|severity.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sort": {
                            "type": "string",
                            "description": "Sort key: count (default) or severity.",
                        },
                        "limit": {"type": "integer", "description": "Max rows (max 10)."},
                    },
                    "required": [],
                },
            ),
            handler=top_finding_rules,
        ),
        Tool(
            spec=ToolSpec(
                name="get_findings_by_rule",
                description="Recent individual findings for one rule id (drill-down after "
                "top_finding_rules or search_findings).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "rule_id": {"type": "string", "description": "The rule id to fetch."},
                        "limit": {"type": "integer", "description": "Max rows (max 10)."},
                    },
                    "required": ["rule_id"],
                },
            ),
            handler=get_findings_by_rule,
        ),
        Tool(
            spec=ToolSpec(
                name="list_anomaly_sources",
                description="List sources that have a statistical anomaly-detection "
                "baseline, with bucket counts and last-updated time.",
                input_schema={"type": "object", "properties": {}, "required": []},
            ),
            handler=list_anomaly_sources,
        ),
        Tool(
            spec=ToolSpec(
                name="get_baseline",
                description="Fetch the trained baseline for one source: per-feature mean "
                "and standard deviation, used to judge whether current activity is "
                "anomalous. Use list_anomaly_sources first to find source keys.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "source": {"type": "string", "description": "The baseline source key."}
                    },
                    "required": ["source"],
                },
            ),
            handler=get_baseline,
        ),
    ]
