"""Notifier abstraction and the shared JSON-POST helper.

A :class:`Notifier` turns a :class:`~logatory.models.Finding` into a message on
some channel (Slack, Discord, a generic webhook, e-mail).  Each notifier carries
its own ``min_severity`` so different channels can have different noise floors —
e.g. e-mail only on ``critical`` while Slack fires on ``high``.

Sending must never raise: the realtime tail loop keeps running even if a channel
is unreachable.  ``send`` returns ``True`` on success and ``False`` on any error.
"""

from __future__ import annotations

import json
import time
import urllib.request
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from logatory.tail_helpers import meets_alert_severity

if TYPE_CHECKING:
    from logatory.models import Finding

# Severity → colour, shared by the chat notifiers.
# Slack wants a hex string; Discord wants a 24-bit integer.
SLACK_COLOR: dict[str, str] = {
    "low": "#36a64f",  # green
    "medium": "#daa038",  # amber
    "high": "#d64b2b",  # orange-red
    "critical": "#a30000",  # dark red
}
DISCORD_COLOR: dict[str, int] = {
    "low": 0x36A64F,
    "medium": 0xDAA038,
    "high": 0xD64B2B,
    "critical": 0xA30000,
}


def mask_url(url: str) -> str:
    """Mask the secret tail of a webhook URL for display (keeps scheme + host)."""
    try:
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        host = parts.netloc or parts.path
        return f"{parts.scheme}://{host}/…" if parts.scheme else f"{host}/…"
    except Exception:
        return "…"


def post_json(url: str, payload: dict, *, timeout: float = 5, headers: dict | None = None) -> bool:
    """POST *payload* as JSON to *url*. Return True on success, False on any error.

    Network and serialisation failures are swallowed by design — an alert channel
    being down must never crash the pipeline that is producing findings.
    """
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False


class Notifier(ABC):
    """Base class for an alert channel.

    Subclasses set :attr:`name` and implement :meth:`send`.  :meth:`matches`
    applies the channel's ``min_severity`` gate so callers can dispatch a finding
    to a list of notifiers and let each decide whether it cares.
    """

    name: str = "notifier"

    def __init__(self, *, min_severity: str = "high", cooldown: float = 0) -> None:
        self.min_severity = min_severity
        self.cooldown = cooldown
        self._last_sent: dict[str, float] = {}

    def matches(self, finding: Finding) -> bool:
        """True if *finding* is severe enough for this channel."""
        return meets_alert_severity(finding, self.min_severity)

    @staticmethod
    def _dedup_key(finding: Finding) -> str:
        """Identity used for throttling: the same rule firing on the same source."""
        return f"{finding.rule_id}\x00{finding.source}"

    def is_throttled(self, finding: Finding, *, now: float | None = None) -> bool:
        """True if an identical finding was delivered within ``cooldown`` seconds."""
        if self.cooldown <= 0:
            return False
        now = time.monotonic() if now is None else now
        last = self._last_sent.get(self._dedup_key(finding))
        return last is not None and (now - last) < self.cooldown

    def record_sent(self, finding: Finding, *, now: float | None = None) -> None:
        """Remember that *finding* was just delivered (for throttling)."""
        if self.cooldown > 0:
            self._last_sent[self._dedup_key(finding)] = time.monotonic() if now is None else now

    @abstractmethod
    def send(self, finding: Finding) -> bool:
        """Deliver *finding*. Return True on success, False on failure."""
        raise NotImplementedError

    def describe(self) -> str:
        """Short human-readable, secret-free description for ``alerts list``."""
        return self.name
