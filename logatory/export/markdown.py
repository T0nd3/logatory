"""Markdown report generator.

Produces a structured security report from findings and errors stored in SQLite.
The report is pure Markdown — no external dependencies required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from logatory.models import FindingSeverity
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository

# Severity display order (most critical first) — derived from the enum so
# new severities pick up automatically when added in models.py.
_SEV_ORDER: list[str] = [s.value for s in sorted(FindingSeverity, key=lambda x: -x.level)]


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a Markdown table."""
    sep = ["-" * max(len(h), 4) for h in headers]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(sep) + " |",
    ]
    lines.extend("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return "\n".join(lines)


def _escape(text: str, max_len: int = 80) -> str:
    """Escape pipe characters for Markdown tables and truncate."""
    s = str(text).replace("|", "\\|").replace("\n", " ")
    return s[:max_len] + "…" if len(s) > max_len else s


def generate_report(
    db_path: Path,
    since_hours: int = 168,
    min_severity: str | None = None,
    title: str = "Logatory Security Report",
) -> str:
    """Generate and return a Markdown report string.

    Args:
        db_path:      Path to the SQLite database.
        since_hours:  How many hours back to include (default 7 days).
        min_severity: Minimum severity to include ("low"|"medium"|"high"|"critical").
        title:        Report title.
    """
    now = datetime.now(tz=UTC)
    generated = now.strftime("%Y-%m-%d %H:%M UTC")

    with FindingsRepository(db_path) as f_repo, ErrorsRepository(db_path) as e_repo:
        f_summary = f_repo.summary()
        e_summary = e_repo.summary()
        recent_findings = f_repo.recent_findings(since_hours=since_hours, severity=min_severity)
        top_rules = f_repo.count_by_rule(limit=10)
        error_groups = e_repo.list_errors(sort="count", limit=20)
        top_errors_new = e_repo.new_errors(since_hours=since_hours)[:5]

    lines: list[str] = []

    # ── Header ─────────────────────────────────────────────────────────
    lines += [
        f"# {title}",
        "",
        f"**Generated:** {generated}  ",
        f"**Period:** Last {since_hours}h",
        f"**Database:** `{db_path}`",
        "",
        "---",
        "",
    ]

    # ── Summary ────────────────────────────────────────────────────────
    lines += ["## Summary", ""]
    sev = f_summary.get("by_severity", {})
    summary_rows = [
        ["Total findings (all time)", str(f_summary.get("total", 0))],
        ["— Critical", str(sev.get("critical", 0))],
        ["— High", str(sev.get("high", 0))],
        ["— Medium", str(sev.get("medium", 0))],
        ["— Low", str(sev.get("low", 0))],
        ["Findings in report period", str(len(recent_findings))],
        ["Error patterns (all time)", str(e_summary.get("total_error_types", 0))],
        ["Error occurrences (all time)", str(e_summary.get("total_occurrences", 0))],
    ]
    lines += [_md_table(["Metric", "Value"], summary_rows), ""]

    # ── Severity breakdown bar ─────────────────────────────────────────
    total = f_summary.get("total", 0)
    if total > 0:
        lines += ["### Severity Distribution", ""]
        for s in _SEV_ORDER:
            n = sev.get(s, 0)
            bar = "█" * min(int(n / max(total, 1) * 30) + (1 if n else 0), 30)
            lines.append(f"- **{s.upper():<8}** {bar} {n}")
        lines.append("")

    # ── Top rules ──────────────────────────────────────────────────────
    if top_rules:
        lines += ["## Top Triggered Rules", ""]
        rule_rows = [
            [_escape(r["rule_id"]), r["severity"].upper(), str(r["count"])] for r in top_rules
        ]
        lines += [_md_table(["Rule ID", "Severity", "Count"], rule_rows), ""]

    # ── Findings in period ─────────────────────────────────────────────
    lines += [f"## Findings (last {since_hours}h)", ""]
    if recent_findings:
        finding_rows = [
            [
                _escape(dict(r)["created_at"][:16]),
                _escape(dict(r)["rule_id"]),
                dict(r)["severity"].upper(),
                _escape(dict(r)["source"], 40),
                _escape(dict(r)["message"], 60),
            ]
            for r in recent_findings[:50]
        ]
        lines += [
            _md_table(["Time (UTC)", "Rule", "Severity", "Source", "Message"], finding_rows),
            "",
        ]
        if len(recent_findings) > 50:
            lines += [f"> *(showing 50 of {len(recent_findings)} findings)*", ""]
    else:
        lines += [f"*No findings in the last {since_hours}h.*", ""]

    # ── New errors in period ───────────────────────────────────────────
    if top_errors_new:
        lines += [f"## New Error Patterns (last {since_hours}h)", ""]
        new_rows = [
            [
                _escape(dict(r)["error_type"], 30),
                dict(r)["severity"].upper(),
                str(dict(r)["count"]),
                _escape(dict(r)["normalized_msg"], 60),
            ]
            for r in top_errors_new
        ]
        lines += [_md_table(["Type", "Severity", "Count", "Normalized Message"], new_rows), ""]

    # ── All error groups ───────────────────────────────────────────────
    if error_groups:
        lines += ["## Error Groups (top 20 by count)", ""]
        err_rows = [
            [
                _escape(dict(r)["error_type"], 30),
                dict(r)["severity"].upper(),
                str(dict(r)["count"]),
                _escape(dict(r)["first_seen"][:16]),
                _escape(dict(r)["last_seen"][:16]),
                _escape(dict(r)["normalized_msg"], 50),
            ]
            for r in error_groups
        ]
        lines += [
            _md_table(
                ["Type", "Severity", "Count", "First seen", "Last seen", "Message"],
                err_rows,
            ),
            "",
        ]

    # ── Footer ─────────────────────────────────────────────────────────
    lines += [
        "---",
        "",
        f"*Generated by [Logatory](https://github.com/T0nd3/logatory) v0.1.0 — {generated}*",
    ]

    return "\n".join(lines) + "\n"
