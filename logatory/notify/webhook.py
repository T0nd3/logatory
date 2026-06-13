"""Generic JSON webhook notifier.

Posts the same flat payload the legacy ``--alert-webhook`` always sent, so
existing webhook receivers keep working unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Notifier, mask_url, post_json

if TYPE_CHECKING:
    from logatory.models import Finding


class WebhookNotifier(Notifier):
    name = "webhook"

    def __init__(
        self,
        *,
        url: str,
        min_severity: str = "high",
        cooldown: float = 0,
        escalate_count: int = 0,
        escalate_window: float = 0,
    ) -> None:
        super().__init__(
            min_severity=min_severity,
            cooldown=cooldown,
            escalate_count=escalate_count,
            escalate_window=escalate_window,
        )
        self.url = url

    def send(self, finding: Finding) -> bool:
        payload = {
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "message": finding.message,
            "source": finding.source,
            "timestamp": finding.timestamp.isoformat(),
        }
        return post_json(self.url, payload)

    def describe(self) -> str:
        return f"webhook → {mask_url(self.url)}"
