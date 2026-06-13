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

from ..storage.errors_repo import ErrorsRepository
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
    ]
