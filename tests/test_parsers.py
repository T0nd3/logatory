from logatory.models import Severity
from logatory.parsers.json_lines import JsonLinesParser
from logatory.parsers.logfmt import LogfmtParser
from logatory.parsers.nginx import NginxCombinedParser
from logatory.parsers.syslog import AuthLogParser, SyslogParser


class TestJsonLinesParser:
    def setup_method(self):
        self.parser = JsonLinesParser("test")

    def test_basic_event(self):
        line = '{"timestamp": "2026-05-18T10:00:00Z", "level": "error", "message": "DB down"}'
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "DB down"
        assert event.severity == Severity.ERROR
        assert event.timestamp is not None

    def test_warning_level_variants(self):
        for level in ("warn", "warning", "WARNING"):
            line = f'{{"level": "{level}", "message": "heads up"}}'
            event = self.parser.parse(line)
            assert event.severity == Severity.WARNING, f"failed for level={level}"

    def test_empty_line_returns_none(self):
        assert self.parser.parse("") is None
        assert self.parser.parse("   ") is None

    def test_non_json_returns_none(self):
        assert self.parser.parse("this is plain text") is None

    def test_parsed_fields_preserved(self):
        line = '{"message": "ok", "service": "api", "attempt": 3}'
        event = self.parser.parse(line)
        assert event.parsed_fields["service"] == "api"
        assert event.parsed_fields["attempt"] == 3

    def test_unix_timestamp(self):
        line = '{"ts": 1747555200, "msg": "boot"}'
        event = self.parser.parse(line)
        assert event is not None
        assert event.timestamp is not None


class TestLogfmtParser:
    def setup_method(self):
        self.parser = LogfmtParser("test")

    def test_basic_event(self):
        line = 'ts=2026-06-07T08:15:04Z level=error msg="db down" service=api'
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "db down"
        assert event.severity == Severity.ERROR
        assert event.timestamp is not None
        assert event.parsed_fields["service"] == "api"

    def test_quoted_value_with_spaces(self):
        event = self.parser.parse('level=info msg="user bob logged in" user=bob')
        assert event.message == "user bob logged in"
        assert event.parsed_fields["user"] == "bob"

    def test_escaped_quote_in_value(self):
        event = self.parser.parse(r'level=info msg="say \"hi\" now"')
        assert event.message == 'say "hi" now'

    def test_level_variants(self):
        for raw, expected in (
            ("warn", Severity.WARNING),
            ("warning", Severity.WARNING),
            ("err", Severity.ERROR),
            ("crit", Severity.CRITICAL),
            ("debug", Severity.DEBUG),
        ):
            event = self.parser.parse(f"level={raw} msg=hello there=1")
            assert event.severity == expected, f"failed for level={raw}"

    def test_unix_timestamp(self):
        event = self.parser.parse("ts=1747555200 level=info msg=boot extra=1")
        assert event is not None
        assert event.timestamp is not None

    def test_bare_values_preserved(self):
        event = self.parser.parse("method=GET path=/health status=200 dur=1.2s")
        assert event.parsed_fields["method"] == "GET"
        assert event.parsed_fields["status"] == "200"
        assert event.parsed_fields["dur"] == "1.2s"

    def test_message_falls_back_to_raw(self):
        # No msg/message key → the whole line is the message.
        event = self.parser.parse("foo=1 bar=2")
        assert event.message == "foo=1 bar=2"

    def test_empty_line_returns_none(self):
        assert self.parser.parse("") is None
        assert self.parser.parse("   ") is None

    def test_no_pairs_returns_none(self):
        assert self.parser.parse("just some plain words here") is None


class TestNginxCombinedParser:
    def setup_method(self):
        self.parser = NginxCombinedParser("nginx")

    def test_200_is_info(self):
        line = '10.0.0.1 - - [18/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "curl"'
        event = self.parser.parse(line)
        assert event is not None
        assert event.severity == Severity.INFO
        assert event.parsed_fields["status"] == 200

    def test_500_is_error(self):
        line = '10.0.0.2 - - [18/May/2026:10:00:00 +0000] "DELETE /api HTTP/1.1" 500 89 "-" "Go"'
        event = self.parser.parse(line)
        assert event.severity == Severity.ERROR

    def test_404_is_warning(self):
        line = (
            '203.0.113.42 - - [18/May/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "bot"'
        )
        event = self.parser.parse(line)
        assert event.severity == Severity.WARNING

    def test_remote_addr_in_fields(self):
        line = '192.168.1.1 - frank [18/May/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 0 "-" "-"'
        event = self.parser.parse(line)
        assert event.parsed_fields["remote_addr"] == "192.168.1.1"

    def test_empty_line_returns_none(self):
        assert self.parser.parse("") is None

    def test_garbage_returns_none(self):
        assert self.parser.parse("not a log line at all") is None


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser("syslog")

    def test_basic_syslog(self):
        line = "May 18 09:55:01 webserver systemd[1]: Starting nginx.service..."
        event = self.parser.parse(line)
        assert event is not None
        assert "nginx" in event.message
        assert event.parsed_fields["process"] == "systemd"
        assert event.parsed_fields["pid"] == "1"

    def test_empty_returns_none(self):
        assert self.parser.parse("") is None


class TestAuthLogParser:
    def setup_method(self):
        self.parser = AuthLogParser("auth.log")

    def test_ssh_accepted(self):
        line = "May 18 10:00:01 webserver sshd[1234]: Accepted publickey for admin from 10.0.0.5 port 52341 ssh2"
        event = self.parser.parse(line)
        assert event is not None
        assert event.parsed_fields["process"] == "sshd"

    def test_failed_password(self):
        line = "May 18 10:00:15 webserver sshd[1235]: Failed password for invalid user guest from 203.0.113.42 port 22 ssh2"
        event = self.parser.parse(line)
        assert event is not None
        assert event.severity == Severity.WARNING
