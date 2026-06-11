"""Tests for the CEF and LEEF security-appliance parsers."""

from __future__ import annotations

from logatory.models import Severity
from logatory.parsers.cef_leef import (
    CEFParser,
    LEEFParser,
    looks_like_cef,
    looks_like_leef,
    parse_cef,
    parse_leef,
)

# ---------------------------------------------------------------------------
# CEF
# ---------------------------------------------------------------------------


class TestCEFParser:
    def setup_method(self):
        self.parser = CEFParser("appliance")

    def test_basic_event(self):
        line = "CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232"
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "worm stopped"
        assert event.severity == Severity.CRITICAL
        assert event.source == "appliance"
        assert event.parsed_fields["cef_vendor"] == "Security"
        assert event.parsed_fields["cef_product"] == "threatmanager"
        assert event.parsed_fields["cef_signature_id"] == "100"
        assert event.parsed_fields["src"] == "10.0.0.1"
        assert event.parsed_fields["dst"] == "2.1.2.2"
        assert event.parsed_fields["spt"] == "1232"

    def test_severity_buckets(self):
        for sev, expected in (
            ("0", Severity.INFO),
            ("3", Severity.INFO),
            ("4", Severity.WARNING),
            ("6", Severity.WARNING),
            ("7", Severity.ERROR),
            ("8", Severity.ERROR),
            ("9", Severity.CRITICAL),
            ("10", Severity.CRITICAL),
        ):
            line = f"CEF:0|V|P|1.0|1|name|{sev}|src=1.1.1.1"
            event = self.parser.parse(line)
            assert event.severity == expected, f"failed for severity={sev}"

    def test_string_severity(self):
        for sev, expected in (
            ("Low", Severity.INFO),
            ("Medium", Severity.WARNING),
            ("High", Severity.ERROR),
            ("Very-High", Severity.CRITICAL),
        ):
            line = f"CEF:0|V|P|1.0|1|name|{sev}|src=1.1.1.1"
            assert self.parser.parse(line).severity == expected

    def test_syslog_prefix_stripped(self):
        line = "Jan  5 12:00:00 fw01 CEF:0|V|FW|1.0|100|blocked|6|src=10.0.0.1"
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "blocked"
        assert event.parsed_fields["cef_product"] == "FW"
        assert event.parsed_fields["src"] == "10.0.0.1"

    def test_escaped_pipe_in_header(self):
        line = r"CEF:0|V|P|1.0|1|a\|b name|5|src=1.1.1.1"
        event = self.parser.parse(line)
        assert event.message == "a|b name"

    def test_escaped_equals_in_value(self):
        line = r"CEF:0|V|P|1.0|1|name|5|src=1.1.1.1 query=a\=b act=blocked"
        event = self.parser.parse(line)
        assert event.parsed_fields["query"] == "a=b"
        assert event.parsed_fields["act"] == "blocked"

    def test_value_with_spaces(self):
        line = "CEF:0|V|P|1.0|1|name|5|src=1.1.1.1 msg=connection was refused dst=2.2.2.2"
        event = self.parser.parse(line)
        assert event.parsed_fields["msg"] == "connection was refused"
        assert event.parsed_fields["dst"] == "2.2.2.2"

    def test_timestamp_from_rt_epoch_millis(self):
        line = "CEF:0|V|P|1.0|1|name|5|rt=1700000000000 src=1.1.1.1"
        event = self.parser.parse(line)
        assert event.timestamp is not None
        assert event.timestamp.year == 2023

    def test_no_extension(self):
        line = "CEF:0|V|P|1.0|1|just a name|5|"
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "just a name"
        assert event.parsed_fields["cef_severity"] == "5"

    def test_too_few_fields_returns_none(self):
        assert self.parser.parse("CEF:0|V|P|1.0") is None

    def test_non_cef_returns_none(self):
        assert self.parser.parse("this is not a cef line") is None

    def test_empty_returns_none(self):
        assert self.parser.parse("") is None
        assert self.parser.parse("   ") is None

    def test_looks_like_cef(self):
        assert looks_like_cef("CEF:0|a|b|c|d|e|1|")
        assert looks_like_cef("prefix CEF:1|a|b|c|d|e|1|x=y")
        assert not looks_like_cef("LEEF:1.0|a|b|c|d|x=y")
        assert not looks_like_cef("just text")

    def test_parse_cef_function_source(self):
        event = parse_cef("CEF:0|V|P|1.0|1|name|5|src=1.1.1.1", "src-name")
        assert event.source == "src-name"


# ---------------------------------------------------------------------------
# LEEF
# ---------------------------------------------------------------------------


class TestLEEFParser:
    def setup_method(self):
        self.parser = LEEFParser("qradar")

    def test_leef_1_0_tab_delimited(self):
        line = "LEEF:1.0|Vendor|Product|1.0|anomaly|src=10.0.0.1\tdst=2.1.2.2\tsev=5\tmsg=traffic anomaly"
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "traffic anomaly"
        assert event.severity == Severity.WARNING
        assert event.parsed_fields["leef_vendor"] == "Vendor"
        assert event.parsed_fields["leef_event_id"] == "anomaly"
        assert event.parsed_fields["src"] == "10.0.0.1"
        assert event.parsed_fields["dst"] == "2.1.2.2"

    def test_leef_2_0_custom_delimiter(self):
        line = "LEEF:2.0|IBM|QRadar|3.1|auth_fail|^|src=192.168.1.5^usrName=bob^sev=7^msg=login failed"
        event = self.parser.parse(line)
        assert event is not None
        assert event.message == "login failed"
        assert event.severity == Severity.ERROR
        assert event.parsed_fields["usrName"] == "bob"
        assert event.parsed_fields["src"] == "192.168.1.5"

    def test_leef_2_0_hex_delimiter(self):
        line = "LEEF:2.0|V|P|1.0|evt|x09|src=10.0.0.1\tdst=2.2.2.2\tsev=3"
        event = self.parser.parse(line)
        assert event.parsed_fields["src"] == "10.0.0.1"
        assert event.parsed_fields["dst"] == "2.2.2.2"

    def test_leef_2_0_default_tab_when_no_delimiter_field(self):
        # LEEF 2.0 without the optional delimiter field falls back to tab.
        line = "LEEF:2.0|V|P|1.0|evt|src=10.0.0.1\tsev=2"
        event = self.parser.parse(line)
        assert event.parsed_fields["src"] == "10.0.0.1"
        assert event.parsed_fields["sev"] == "2"

    def test_message_falls_back_to_event_id(self):
        line = "LEEF:1.0|V|P|1.0|the_event|src=10.0.0.1\tsev=1"
        event = self.parser.parse(line)
        assert event.message == "the_event"

    def test_severity_default_info(self):
        line = "LEEF:1.0|V|P|1.0|evt|src=10.0.0.1\tdst=2.2.2.2"
        event = self.parser.parse(line)
        assert event.severity == Severity.INFO

    def test_syslog_prefix_stripped(self):
        line = "Jan  5 12:00:00 host LEEF:1.0|V|P|1.0|evt|src=10.0.0.1\tsev=7"
        event = self.parser.parse(line)
        assert event is not None
        assert event.severity == Severity.ERROR
        assert event.parsed_fields["src"] == "10.0.0.1"

    def test_devtime_timestamp(self):
        line = "LEEF:1.0|V|P|1.0|evt|src=10.0.0.1\tdevTime=1700000000000\tsev=2"
        event = self.parser.parse(line)
        assert event.timestamp is not None
        assert event.timestamp.year == 2023

    def test_too_few_fields_returns_none(self):
        assert self.parser.parse("LEEF:1.0|V|P") is None

    def test_non_leef_returns_none(self):
        assert self.parser.parse("not a leef line") is None

    def test_empty_returns_none(self):
        assert self.parser.parse("") is None
        assert self.parser.parse("   ") is None

    def test_looks_like_leef(self):
        assert looks_like_leef("LEEF:1.0|a|b|c|d|x=y")
        assert looks_like_leef("LEEF:2.0|a|b|c|d|^|x=y")
        assert looks_like_leef("prefix LEEF:1.0|a|b|c|d|x=y")
        assert not looks_like_leef("CEF:0|a|b|c|d|e|1|")
        assert not looks_like_leef("plain text")

    def test_parse_leef_function_source(self):
        event = parse_leef("LEEF:1.0|V|P|1.0|evt|src=1.1.1.1", "src-name")
        assert event.source == "src-name"
