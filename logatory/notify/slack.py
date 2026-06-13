"""Slack Incoming-Webhook notifier — coloured attachment per finding."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import SLACK_COLOR, Notifier, mask_url, post_json

if TYPE_CHECKING:
    from logatory.models import Finding


class SlackNotifier(Notifier):
    name = "slack"

    def __init__(self, *, url: str, min_severity: str = "high") -> None:
        super().__init__(min_severity=min_severity)
        self.url = url

    def send(self, finding: Finding) -> bool:
        sev = finding.severity.value
        payload = {
            "attachments": [
                {
                    "color": SLACK_COLOR.get(sev, "#cccccc"),
                    "fallback": f"[{sev.upper()}] {finding.rule_id}: {finding.message}",
                    "title": f"{sev.upper()} — {finding.rule_id}",
                    "text": finding.message,
                    "fields": [
                        {"title": "Source", "value": finding.source, "short": True},
                        {"title": "Time", "value": finding.timestamp.isoformat(), "short": True},
                    ],
                }
            ]
        }
        return post_json(self.url, payload)

    def describe(self) -> str:
        return f"slack → {mask_url(self.url)}"
