"""Tests for the alert notification system (logatory.notify + config + CLI)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from logatory.config import AlertChannel, Config
from logatory.models import Finding, FindingSeverity
from logatory.notify import (
    DiscordNotifier,
    EmailNotifier,
    SlackNotifier,
    WebhookNotifier,
    build_notifier,
    build_notifiers,
    dispatch,
)
from logatory.notify.base import mask_url

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _finding(sev: FindingSeverity = FindingSeverity.CRITICAL) -> Finding:
    return Finding(
        rule_id="TEST",
        severity=sev,
        message="something happened",
        source="app.log",
        timestamp=datetime(2026, 6, 13, 8, 15, 4, tzinfo=UTC),
    )


@pytest.fixture
def capture_post(monkeypatch):
    """Capture urllib POSTs without hitting the network. Returns the request list."""
    sent: list = []

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(req, timeout=None):
        sent.append(req)
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return sent


@pytest.fixture
def fail_post(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)


# ---------------------------------------------------------------------------
# Payload formatting
# ---------------------------------------------------------------------------


class TestWebhookNotifier:
    def test_posts_flat_json(self, capture_post):
        ok = WebhookNotifier(url="http://x/hook").send(_finding())
        assert ok is True
        assert len(capture_post) == 1
        body = json.loads(capture_post[0].data)
        assert body == {
            "rule_id": "TEST",
            "severity": "critical",
            "message": "something happened",
            "source": "app.log",
            "timestamp": "2026-06-13T08:15:04+00:00",
        }
        assert capture_post[0].full_url == "http://x/hook"

    def test_failure_returns_false(self, fail_post):
        assert WebhookNotifier(url="http://x/hook").send(_finding()) is False


class TestSlackNotifier:
    def test_attachment_structure_and_color(self, capture_post):
        SlackNotifier(url="https://hooks.slack.com/y").send(_finding(FindingSeverity.HIGH))
        body = json.loads(capture_post[0].data)
        att = body["attachments"][0]
        assert att["color"] == "#d64b2b"  # high
        assert "HIGH" in att["title"]
        assert att["text"] == "something happened"
        titles = {f["title"] for f in att["fields"]}
        assert {"Source", "Time"} <= titles


class TestDiscordNotifier:
    def test_embed_structure_and_int_color(self, capture_post):
        DiscordNotifier(url="https://discord.com/api/webhooks/z").send(_finding())
        body = json.loads(capture_post[0].data)
        emb = body["embeds"][0]
        assert emb["color"] == 0xA30000  # critical, integer not string
        assert emb["description"] == "something happened"
        names = {f["name"] for f in emb["fields"]}
        assert {"Source", "Time"} <= names


# ---------------------------------------------------------------------------
# Email (SMTP)
# ---------------------------------------------------------------------------


class _FakeSMTP:
    instances: ClassVar[list] = []

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.started_tls = False
        self.logged = None
        self.sent = []
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.started_tls = True

    def login(self, user, password):
        self.logged = (user, password)

    def send_message(self, msg):
        self.sent.append(msg)


class TestEmailNotifier:
    def test_sends_with_tls_and_auth(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("smtplib.SMTP", _FakeSMTP)
        ok = EmailNotifier(
            smtp_host="mail.example.com",
            smtp_port=587,
            smtp_user="bot",
            smtp_password="secret",
            recipients=["ops@example.com"],
        ).send(_finding())
        assert ok is True
        smtp = _FakeSMTP.instances[0]
        assert smtp.host == "mail.example.com"
        assert smtp.started_tls is True
        assert smtp.logged == ("bot", "secret")
        msg = smtp.sent[0]
        assert msg["To"] == "ops@example.com"
        assert "CRITICAL" in msg["Subject"]

    def test_no_auth_when_creds_missing(self, monkeypatch):
        _FakeSMTP.instances = []
        monkeypatch.setattr("smtplib.SMTP", _FakeSMTP)
        EmailNotifier(smtp_host="localhost", use_tls=False, recipients=["a@b.de"]).send(_finding())
        smtp = _FakeSMTP.instances[0]
        assert smtp.started_tls is False
        assert smtp.logged is None

    def test_failure_returns_false(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("smtp down")

        monkeypatch.setattr("smtplib.SMTP", boom)
        assert EmailNotifier(smtp_host="x", recipients=["a@b.de"]).send(_finding()) is False


# ---------------------------------------------------------------------------
# Severity gating
# ---------------------------------------------------------------------------


class TestMatches:
    def test_high_channel_ignores_medium(self):
        n = WebhookNotifier(url="http://x", min_severity="high")
        assert n.matches(_finding(FindingSeverity.MEDIUM)) is False
        assert n.matches(_finding(FindingSeverity.HIGH)) is True

    def test_critical_channel_only_critical(self):
        n = WebhookNotifier(url="http://x", min_severity="critical")
        assert n.matches(_finding(FindingSeverity.HIGH)) is False
        assert n.matches(_finding(FindingSeverity.CRITICAL)) is True


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


class TestBuildNotifier:
    def test_builds_each_type(self):
        assert isinstance(build_notifier(AlertChannel("webhook", url="http://x")), WebhookNotifier)
        assert isinstance(build_notifier(AlertChannel("slack", url="http://x")), SlackNotifier)
        assert isinstance(build_notifier(AlertChannel("discord", url="http://x")), DiscordNotifier)
        email = build_notifier(AlertChannel("email", smtp_host="h", recipients=["a@b.de"]))
        assert isinstance(email, EmailNotifier)

    def test_url_type_without_url_raises(self):
        with pytest.raises(ValueError, match="requires a 'url'"):
            build_notifier(AlertChannel("slack"))

    def test_email_without_recipients_raises(self):
        with pytest.raises(ValueError, match="smtp_host' and 'recipients'"):
            build_notifier(AlertChannel("email", smtp_host="h"))

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown alert channel type"):
            build_notifier(AlertChannel("pager"))

    def test_legacy_webhook_appended(self):
        ns = build_notifiers([], alert_webhook="http://legacy", alert_min_severity="low")
        assert len(ns) == 1
        assert isinstance(ns[0], WebhookNotifier)
        assert ns[0].min_severity == "low"


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_counts_only_matching_channels(self, capture_post):
        notifiers = [
            WebhookNotifier(url="http://a", min_severity="high"),
            WebhookNotifier(url="http://b", min_severity="critical"),
        ]
        # HIGH finding → only the first channel fires.
        assert dispatch(notifiers, _finding(FindingSeverity.HIGH)) == 1
        # CRITICAL → both fire.
        assert dispatch(notifiers, _finding(FindingSeverity.CRITICAL)) == 2

    def test_failed_send_not_counted(self, fail_post):
        notifiers = [WebhookNotifier(url="http://a", min_severity="low")]
        assert dispatch(notifiers, _finding()) == 0


# ---------------------------------------------------------------------------
# Throttling / dedup
# ---------------------------------------------------------------------------


class TestThrottle:
    def test_cooldown_zero_never_throttles(self):
        n = WebhookNotifier(url="http://x", min_severity="low")  # cooldown defaults to 0
        n.record_sent(_finding(), now=100.0)
        assert n.is_throttled(_finding(), now=100.0) is False

    def test_throttled_within_window(self):
        n = WebhookNotifier(url="http://x", min_severity="low", cooldown=300)
        assert n.is_throttled(_finding(), now=1000.0) is False  # nothing sent yet
        n.record_sent(_finding(), now=1000.0)
        assert n.is_throttled(_finding(), now=1200.0) is True  # 200s < 300s

    def test_allowed_after_window(self):
        n = WebhookNotifier(url="http://x", min_severity="low", cooldown=300)
        n.record_sent(_finding(), now=1000.0)
        assert n.is_throttled(_finding(), now=1400.0) is False  # 400s > 300s

    def test_distinct_findings_tracked_separately(self):
        n = WebhookNotifier(url="http://x", min_severity="low", cooldown=300)
        a = Finding(
            rule_id="A",
            severity=FindingSeverity.HIGH,
            message="m",
            source="s1",
            timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        )
        b = Finding(
            rule_id="B",
            severity=FindingSeverity.HIGH,
            message="m",
            source="s1",
            timestamp=datetime(2026, 6, 13, tzinfo=UTC),
        )
        n.record_sent(a, now=1000.0)
        assert n.is_throttled(a, now=1100.0) is True
        assert n.is_throttled(b, now=1100.0) is False  # different rule_id

    def test_dispatch_suppresses_repeat(self, capture_post, monkeypatch):
        clock = {"t": 1000.0}
        monkeypatch.setattr("time.monotonic", lambda: clock["t"])
        notifiers = [WebhookNotifier(url="http://a", min_severity="low", cooldown=300)]

        assert dispatch(notifiers, _finding()) == 1  # first delivered
        assert dispatch(notifiers, _finding()) == 0  # throttled, suppressed
        clock["t"] = 1400.0
        assert dispatch(notifiers, _finding()) == 1  # window elapsed
        assert len(capture_post) == 2

    def test_dispatch_failed_send_not_recorded(self, fail_post, monkeypatch):
        monkeypatch.setattr("time.monotonic", lambda: 1000.0)
        n = WebhookNotifier(url="http://a", min_severity="low", cooldown=300)
        assert dispatch([n], _finding()) == 0
        # The failed send must not have armed the cooldown.
        assert n.is_throttled(_finding(), now=1000.0) is False


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


class TestAlertChannelConfig:
    def test_from_dict_defaults_and_lowercasing(self):
        ch = AlertChannel.from_dict({"type": "SLACK", "url": "http://x"})
        assert ch.type == "slack"
        assert ch.min_severity == "high"
        assert ch.smtp_port == 587
        assert ch.use_tls is True

    def test_env_var_expansion_in_url(self, monkeypatch):
        monkeypatch.setenv("MY_HOOK", "https://hooks.slack.com/secret")
        ch = AlertChannel.from_dict({"type": "slack", "url": "${MY_HOOK}"})
        assert ch.url == "https://hooks.slack.com/secret"

    def test_env_var_expansion_in_smtp_password(self, monkeypatch):
        monkeypatch.setenv("SMTP_PW", "s3cr3t")
        ch = AlertChannel.from_dict(
            {
                "type": "email",
                "smtp_host": "h",
                "recipients": ["a@b.de"],
                "smtp_password": "$SMTP_PW",
            }
        )
        assert ch.smtp_password == "s3cr3t"

    def test_config_load_parses_alerts(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(
            "alerts:\n"
            "  - type: slack\n"
            "    url: http://hooks/x\n"
            "    min_severity: critical\n"
            "  - type: webhook\n"
            "    url: http://wh/y\n",
            encoding="utf-8",
        )
        cfg = Config.load(cfg_file)
        assert len(cfg.alerts) == 2
        assert cfg.alerts[0].type == "slack"
        assert cfg.alerts[0].min_severity == "critical"

    def test_config_load_no_alerts_is_empty_list(self, tmp_path):
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("db_path: x.db\n", encoding="utf-8")
        assert Config.load(cfg_file).alerts == []

    def test_cooldown_defaults_to_zero(self):
        assert AlertChannel.from_dict({"type": "slack", "url": "http://x"}).cooldown == 0

    def test_cooldown_parsed(self):
        ch = AlertChannel.from_dict({"type": "slack", "url": "http://x", "cooldown": 300})
        assert ch.cooldown == 300

    def test_build_notifier_forwards_cooldown(self):
        n = build_notifier(AlertChannel("webhook", url="http://x", cooldown=120))
        assert n.cooldown == 120


# ---------------------------------------------------------------------------
# mask_url
# ---------------------------------------------------------------------------


class TestMaskUrl:
    def test_keeps_host_hides_path(self):
        assert (
            mask_url("https://hooks.slack.com/services/T/B/secret") == "https://hooks.slack.com/…"
        )


# ---------------------------------------------------------------------------
# CLI: alerts list / test
# ---------------------------------------------------------------------------


class TestAlertsCLI:
    def _write_cfg(self, tmp_path, body: str):
        p = tmp_path / "config.yaml"
        p.write_text(body, encoding="utf-8")
        return p

    def test_list_no_channels(self, tmp_path):
        from logatory.cli.alerts_cmd import app

        cfg = self._write_cfg(tmp_path, "db_path: x.db\n")
        res = CliRunner().invoke(app, ["list", "--config", str(cfg)])
        assert res.exit_code == 0
        assert "No alert channels" in res.stdout

    def test_list_shows_channels(self, tmp_path):
        from logatory.cli.alerts_cmd import app

        cfg = self._write_cfg(
            tmp_path, "alerts:\n  - type: slack\n    url: https://hooks.slack.com/abc\n"
        )
        res = CliRunner().invoke(app, ["list", "--config", str(cfg)])
        assert res.exit_code == 0
        assert "slack" in res.stdout

    def test_list_invalid_config_exits_1(self, tmp_path):
        from logatory.cli.alerts_cmd import app

        cfg = self._write_cfg(tmp_path, "alerts:\n  - type: slack\n")  # missing url
        res = CliRunner().invoke(app, ["list", "--config", str(cfg)])
        assert res.exit_code == 1

    def test_test_sends_to_webhook(self, tmp_path, capture_post):
        from logatory.cli.alerts_cmd import app

        cfg = self._write_cfg(tmp_path, "db_path: x.db\n")
        res = CliRunner().invoke(app, ["test", "--config", str(cfg), "--webhook", "http://x/hook"])
        assert res.exit_code == 0
        assert len(capture_post) == 1

    def test_test_no_channels_exits_0(self, tmp_path):
        from logatory.cli.alerts_cmd import app

        cfg = self._write_cfg(tmp_path, "db_path: x.db\n")
        res = CliRunner().invoke(app, ["test", "--config", str(cfg)])
        assert res.exit_code == 0
        assert "nothing to test" in res.stdout
