"""Alert notifications: dispatch findings to Slack, Discord, webhooks, e-mail."""

from __future__ import annotations

from .base import Notifier
from .discord import DiscordNotifier
from .email import EmailNotifier
from .factory import build_notifier, build_notifiers, dispatch
from .slack import SlackNotifier
from .webhook import WebhookNotifier

__all__ = [
    "DiscordNotifier",
    "EmailNotifier",
    "Notifier",
    "SlackNotifier",
    "WebhookNotifier",
    "build_notifier",
    "build_notifiers",
    "dispatch",
]
