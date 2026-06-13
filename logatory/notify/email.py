"""E-mail (SMTP) notifier.

Sends a short plain-text message per finding.  TLS via STARTTLS is on by default;
authentication is used only when both ``smtp_user`` and ``smtp_password`` are set
(so unauthenticated relays / local MTAs work too).
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import TYPE_CHECKING

from .base import Notifier

if TYPE_CHECKING:
    from logatory.models import Finding


class EmailNotifier(Notifier):
    name = "email"

    def __init__(
        self,
        *,
        smtp_host: str,
        recipients: list[str],
        smtp_port: int = 587,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        use_tls: bool = True,
        sender: str | None = None,
        min_severity: str = "high",
        cooldown: float = 0,
    ) -> None:
        super().__init__(min_severity=min_severity, cooldown=cooldown)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.use_tls = use_tls
        self.sender = sender or smtp_user or "logatory@localhost"
        self.recipients = recipients

    def _build_message(self, finding: Finding) -> EmailMessage:
        msg = EmailMessage()
        sev = finding.severity.value
        msg["Subject"] = f"[logatory] {sev.upper()} — {finding.rule_id}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(
            f"Rule:     {finding.rule_id}\n"
            f"Severity: {sev}\n"
            f"Source:   {finding.source}\n"
            f"Time:     {finding.timestamp.isoformat()}\n\n"
            f"{finding.message}\n"
        )
        return msg

    def send(self, finding: Finding) -> bool:
        try:
            msg = self._build_message(finding)
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
                if self.use_tls:
                    smtp.starttls()
                if self.smtp_user and self.smtp_password:
                    smtp.login(self.smtp_user, self.smtp_password)
                smtp.send_message(msg)
            return True
        except Exception:
            return False

    def describe(self) -> str:
        return f"email → {', '.join(self.recipients)} via {self.smtp_host}:{self.smtp_port}"
