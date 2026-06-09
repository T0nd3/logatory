import pytest

from logatory.pii.redactor import PIIRedactor, RedactMode


@pytest.fixture
def redactor():
    return PIIRedactor(salt="test-salt-123", mode=RedactMode.REDACT)


@pytest.fixture
def mask_redactor():
    return PIIRedactor(salt="test-salt-123", mode=RedactMode.MASK)


@pytest.fixture
def dry_run_redactor():
    return PIIRedactor(salt="test-salt-123", mode=RedactMode.DRY_RUN)


class TestPIIRedactor:
    def test_email_redacted(self, redactor):
        result = redactor.redact("User ben@example.com logged in")
        assert "ben@example.com" not in result.text
        assert len(result.hits) == 1

    def test_email_deterministic(self, redactor):
        r1 = redactor.redact("from: ben@example.com")
        r2 = redactor.redact("to: ben@example.com")
        token1 = r1.text.split("from: ")[1]
        token2 = r2.text.split("to: ")[1]
        assert token1 == token2, "same email must produce same hash"

    def test_different_emails_different_hashes(self, redactor):
        r1 = redactor.redact("ben@example.com")
        r2 = redactor.redact("anna@example.com")
        assert r1.text != r2.text

    def test_ipv4_redacted(self, redactor):
        result = redactor.redact("Request from 203.0.113.42 blocked")
        assert "203.0.113.42" not in result.text
        assert len(result.hits) == 1

    def test_mask_mode(self, mask_redactor):
        result = mask_redactor.redact("User ben@example.com connected")
        assert "<EMAIL>" in result.text
        assert "ben@example.com" not in result.text

    def test_no_pii_no_hits(self, redactor):
        result = redactor.redact("Server started successfully on port 8080")
        assert result.hits == []
        assert result.text == "Server started successfully on port 8080"

    def test_iban_redacted(self, redactor):
        result = redactor.redact("Transfer to DE89370400440532013000 processed")
        assert "DE89370400440532013000" not in result.text

    def test_valid_credit_card_redacted(self, redactor):
        # 4532015112830366 is a valid Luhn test number
        result = redactor.redact("Card 4532015112830366 charged")
        assert "4532015112830366" not in result.text

    def test_invalid_credit_card_not_redacted(self, redactor):
        # 1234567890123456 fails Luhn
        result = redactor.redact("Number 1234567890123456 in log")
        assert "1234567890123456" in result.text

    def test_multiple_pii_in_one_line(self, redactor):
        result = redactor.redact("User ben@example.com from 10.0.0.1 logged in")
        assert "ben@example.com" not in result.text
        assert "10.0.0.1" not in result.text
        assert len(result.hits) == 2

    def test_german_phone_redacted(self, redactor):
        for number in ("+49 30 12345678", "0151 23456789", "030 1234567", "0049301234567"):
            result = redactor.redact(f"call {number} now")
            assert number not in result.text, number
            assert any(repl.startswith("phone_") for _, repl in result.hits), number

    def test_timestamp_not_treated_as_phone(self, redactor):
        # Regression: the phone pattern used to eat date/time fragments like
        # "06-07 08" inside an ISO timestamp, corrupting the value.
        original = "2026-06-07 08:15:04.431 ERROR something failed"
        result = redactor.redact(original)
        assert result.text == original
        assert result.hits == []


class TestDryRunRedactor:
    """DRY_RUN reports matches but leaves the input text unchanged."""

    def test_text_is_unchanged(self, dry_run_redactor):
        original = "User ben@example.com from 10.0.0.1 logged in"
        result = dry_run_redactor.redact(original)
        assert result.text == original

    def test_hits_still_recorded(self, dry_run_redactor):
        result = dry_run_redactor.redact("User ben@example.com from 10.0.0.1 logged in")
        assert len(result.hits) == 2

    def test_no_pii_no_hits(self, dry_run_redactor):
        result = dry_run_redactor.redact("Server started successfully on port 8080")
        assert result.text == "Server started successfully on port 8080"
        assert result.hits == []
