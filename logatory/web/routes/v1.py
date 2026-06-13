"""REST API v1 — JSON endpoints protected by optional Bearer token auth.

Base path: /api/v1/

Endpoints:
  GET  /health              health check (no auth)
  GET  /findings            list findings
  GET  /findings/{id}       single finding
  GET  /errors              list error groups
  GET  /errors/{fingerprint} single error + recent occurrences
  GET  /stats               aggregate stats
  POST /events              ingest a raw log line → returns triggered findings
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from logatory.config import Config
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository

from ..auth import require_token
from ..deps import errors_repo, findings_repo, get_config

# ---------------------------------------------------------------------------
# Routers — health is open, everything else requires auth
# ---------------------------------------------------------------------------

health_router = APIRouter(tags=["health"])
router = APIRouter(
    dependencies=[Depends(require_token)],
    tags=["v1"],
)


# ---------------------------------------------------------------------------
# Pydantic response / request models
# ---------------------------------------------------------------------------


class FindingOut(BaseModel):
    id: Optional[int] = None
    rule_id: str
    severity: str
    message: str
    source: str
    event_timestamp: str
    created_at: str


class ErrorOut(BaseModel):
    fingerprint: str
    error_type: str
    normalized_msg: str
    severity: str
    count: int
    first_seen: str
    last_seen: str
    sources: str  # JSON-encoded list


class StatsOut(BaseModel):
    findings_total: int
    findings_by_severity: dict[str, int]
    error_types: int
    error_occurrences: int


class EventIn(BaseModel):
    """A single raw log line to be parsed and evaluated by the rule engine."""

    raw: str
    source: str = "api-ingest"
    format: Optional[str] = None  # syslog | nginx | json_lines | logfmt | plaintext


class EventOut(BaseModel):
    parsed: bool
    findings: list[dict]


# ---------------------------------------------------------------------------
# Health (unauthenticated)
# ---------------------------------------------------------------------------


@health_router.get("/health", summary="Health check")
def health() -> dict:
    """Returns {status: ok, version: ...}. No auth required. Use for liveness probes."""
    from logatory import __version__

    return {"status": "ok", "version": __version__}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@router.get("/findings", response_model=list[FindingOut], summary="List findings")
def v1_findings(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    since_hours: Optional[int] = None,
    limit: int = 100,
    f_repo: FindingsRepository = Depends(findings_repo),
) -> list[dict]:
    """Return persisted findings, newest first.

    Filter by `severity`, `source`, or `since_hours` (relative to now).
    """
    if since_hours:
        rows = f_repo.recent_findings(
            since_hours=since_hours,
            severity=severity or None,
            source=source or None,
        )
        return [dict(r) for r in rows[:limit]]
    return [
        dict(r)
        for r in f_repo.list_findings(
            severity=severity or None, source=source or None, limit=limit
        )
    ]


@router.get("/findings/{finding_id}", response_model=FindingOut, summary="Get finding by ID")
def v1_finding(
    finding_id: int,
    f_repo: FindingsRepository = Depends(findings_repo),
) -> dict:
    """Return a single finding by its database ID."""
    row = f_repo.get_by_id(finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return dict(row)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


@router.get("/errors", response_model=list[ErrorOut], summary="List error groups")
def v1_errors(
    severity: Optional[str] = None,
    sort: str = "last_seen",
    limit: int = 100,
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> list[dict]:
    """Return error groups (deduplicated by fingerprint), newest first.

    `sort` accepts: last_seen (default) | count | first_seen.
    """
    return [dict(r) for r in e_repo.list_errors(sort=sort, severity=severity or None, limit=limit)]


@router.get("/errors/{fingerprint}", summary="Get error group with occurrences")
def v1_error(
    fingerprint: str,
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> dict:
    """Return a single error group and its 20 most recent occurrences."""
    row = e_repo.get_error(fingerprint)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Error not found.")
    occurrences = [dict(o) for o in e_repo.get_occurrences(fingerprint, limit=20)]
    return {"error": dict(row), "occurrences": occurrences}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=StatsOut, summary="Aggregate statistics")
def v1_stats(
    f_repo: FindingsRepository = Depends(findings_repo),
    e_repo: ErrorsRepository = Depends(errors_repo),
) -> dict:
    """Return aggregate counts for findings and errors."""
    f_sum = f_repo.summary()
    e_sum = e_repo.summary()
    return {
        "findings_total": f_sum["total"],
        "findings_by_severity": f_sum["by_severity"],
        "error_types": e_sum["total_error_types"],
        "error_occurrences": e_sum["total_occurrences"],
    }


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------


@router.post("/events", response_model=EventOut, summary="Ingest a log event")
def v1_ingest(
    payload: EventIn,
    request: Request,
    cfg: Config = Depends(get_config),
) -> dict:
    """Parse a single raw log line and evaluate it against built-in rules.

    Returns any triggered findings. Events are NOT persisted — use
    `logatory scan --track-errors` for batch persistence.

    **format** (optional): `syslog`, `nginx`, `json_lines`, `logfmt`, `cef`,
    `leef`, `plaintext`. Auto-detected if omitted.
    """
    from logatory.parsers.detector import FormatDetector, LogFormat
    from logatory.parsers.registry import get_parser

    # Resolve format
    if payload.format:
        try:
            fmt: LogFormat | str = LogFormat(payload.format)
        except ValueError:
            valid = ", ".join(f.value for f in LogFormat)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Unknown format '{payload.format}'. Valid values: {valid}.",
            )
    else:
        fmt = FormatDetector().detect([payload.raw], path=None)

    # Parse the raw line
    parser = get_parser(fmt, source=payload.source)
    event = parser.parse(payload.raw)

    if event is None:
        return {"parsed": False, "findings": []}

    # PII redaction — apply before rule engine so findings never contain raw PII
    from logatory.pii.redactor import PIIRedactor

    redactor = PIIRedactor.from_config(
        salt=cfg.pii_salt,
        rules_path=cfg.pii_rules_path,
    )
    event.message = redactor.redact(event.message).text
    event.raw = redactor.redact(event.raw).text

    # Rule engine — loaded at startup via lifespan; lazy-init as fallback
    from logatory.rules.engine import RuleEngine

    if not hasattr(request.app.state, "rule_engine"):
        from pathlib import Path

        from logatory.rules.loader import load_rules_dir

        _builtin = Path(__file__).parent.parent.parent / "rules" / "builtin"
        request.app.state.rule_engine = RuleEngine(list(load_rules_dir(_builtin)))

    rule_engine: RuleEngine = request.app.state.rule_engine
    findings = rule_engine.process(event)

    return {
        "parsed": True,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "source": f.source,
                "timestamp": f.timestamp.isoformat(),
            }
            for f in findings
        ],
    }
