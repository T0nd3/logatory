"""Shared async pipeline helpers for the realtime ``*_tail`` CLI commands.

Every ``logatory <source> tail`` command (file, docker, journald, ssh,
loki, graylog, opensearch) used to carry an identical ~35-line async
loop: open the optional findings/errors/dismiss repos, drain the
adapter's event stream, redact PII, run the rule engine with dismiss
filter, fire webhook alerts, persist findings/errors, count everything,
close the repos in a finally.

:func:`run_tail_pipeline` is that loop, parameterised on the *event
stream* so the caller picks between ``adapter.events()`` (continuous
sources like file tail) and ``adapter.poll(interval)`` (HTTP / docker
polling).  The caller still owns ``asyncio.run`` plus the surrounding
``KeyboardInterrupt`` handling and the pre/post echo formatting — this
helper only runs the inner pipeline.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

from logatory.config import Config
from logatory.errors.tracker import ErrorTracker
from logatory.models import Event, Finding
from logatory.notify import build_notifiers, dispatch
from logatory.pii.redactor import PIIRedactor
from logatory.rules.engine import RuleEngine
from logatory.storage.dismiss_repo import DismissRepository
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository, meets_min_severity


async def run_tail_pipeline(
    *,
    event_stream: AsyncIterator[Event],
    redactor: PIIRedactor,
    engine: RuleEngine | None,
    counts: dict[str, int],
    cfg: Config,
    print_finding: Callable[[Finding], None],
    track_errors: bool = False,
    track_findings: bool = False,
    alert_webhook: str | None = None,
    alert_min_severity: str = "high",
) -> None:
    """Drive the shared tail pipeline over *event_stream*.

    Updates ``counts`` in place — expected keys: ``events``, ``findings``,
    ``pii``, ``errors``, ``webhooks``.  The caller owns the dict so the
    summary line still has the latest numbers after a ``KeyboardInterrupt``.

    Repository lifecycle: opens ``ErrorsRepository`` when *track_errors*,
    ``FindingsRepository`` when *track_findings*, and ``DismissRepository``
    whenever the rule engine is on.  All three are closed in ``finally``.

    ``print_finding`` is called for every finding that survives the dismiss
    filter — each CLI passes its own formatter (some prefix the target /
    container, others don't).
    """
    e_repo: ErrorsRepository | None = None
    tracker: ErrorTracker | None = None
    f_repo: FindingsRepository | None = None
    d_repo: DismissRepository | None = None

    if track_errors:
        e_repo = ErrorsRepository(cfg.db_path)
        e_repo.open()
        tracker = ErrorTracker(e_repo)
    if track_findings:
        f_repo = FindingsRepository(cfg.db_path)
        f_repo.open()
    if engine:
        d_repo = DismissRepository(cfg.db_path)
        d_repo.open()

    # Build alert channels once: config-driven plus the legacy --alert-webhook.
    notifiers = build_notifiers(
        cfg.alerts, alert_webhook=alert_webhook, alert_min_severity=alert_min_severity
    )

    try:
        async for event in event_stream:
            # PII redaction — every nested layer sees the redacted form.
            result = redactor.redact(event.message)
            event.message = result.text
            event.raw = redactor.redact(event.raw).text
            counts["pii"] += len(result.hits)
            counts["events"] += 1

            # Rule engine + dismiss filter + alerts + persistence.
            if engine:
                for finding in engine.process(event):
                    if d_repo and d_repo.is_dismissed(finding.rule_id, finding.source):
                        continue
                    print_finding(finding)
                    counts["findings"] += 1
                    counts["webhooks"] += dispatch(notifiers, finding)
                    if f_repo and meets_min_severity(finding, cfg.findings_min_severity):
                        f_repo.add_findings([finding])

            # Error tracking (independent of the rule engine).
            if tracker and tracker.process(event) is not None:
                counts["errors"] += 1
    finally:
        if e_repo:
            e_repo.close()
        if f_repo:
            f_repo.close()
        if d_repo:
            d_repo.close()
