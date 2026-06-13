"""Build notifiers from config and dispatch findings to them."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import Notifier
from .discord import DiscordNotifier
from .email import EmailNotifier
from .slack import SlackNotifier
from .webhook import WebhookNotifier

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from logatory.config import AlertChannel
    from logatory.models import Finding

_URL_TYPES = {"webhook": WebhookNotifier, "slack": SlackNotifier, "discord": DiscordNotifier}


def build_notifier(channel: AlertChannel) -> Notifier:
    """Construct a single notifier from a config channel.

    Raises ``ValueError`` on an unknown type or missing required fields so that
    misconfiguration surfaces at startup rather than silently dropping alerts.
    """
    t = channel.type
    if t in _URL_TYPES:
        if not channel.url:
            raise ValueError(f"Alert channel '{t}' requires a 'url'.")
        return _URL_TYPES[t](url=channel.url, min_severity=channel.min_severity)
    if t == "email":
        if not channel.smtp_host or not channel.recipients:
            raise ValueError("Alert channel 'email' requires 'smtp_host' and 'recipients'.")
        return EmailNotifier(
            smtp_host=channel.smtp_host,
            smtp_port=channel.smtp_port,
            smtp_user=channel.smtp_user,
            smtp_password=channel.smtp_password,
            use_tls=channel.use_tls,
            sender=channel.sender,
            recipients=channel.recipients,
            min_severity=channel.min_severity,
        )
    raise ValueError(f"Unknown alert channel type '{t}'. Valid: webhook, slack, discord, email.")


def build_notifiers(
    channels: Iterable[AlertChannel],
    *,
    alert_webhook: str | None = None,
    alert_min_severity: str = "high",
) -> list[Notifier]:
    """Build all configured notifiers, plus a legacy ``--alert-webhook`` if given.

    The legacy flag is appended as an extra :class:`WebhookNotifier` so the old
    behaviour keeps working alongside config-driven channels.
    """
    notifiers = [build_notifier(ch) for ch in channels]
    if alert_webhook:
        notifiers.append(WebhookNotifier(url=alert_webhook, min_severity=alert_min_severity))
    return notifiers


def dispatch(notifiers: Sequence[Notifier], finding: Finding) -> int:
    """Send *finding* to every notifier that wants it. Return the number delivered."""
    sent = 0
    for n in notifiers:
        if n.matches(finding) and n.send(finding):
            sent += 1
    return sent
