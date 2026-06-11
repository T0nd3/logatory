from pathlib import Path

from logatory.parsers.detector import FormatDetector, LogFormat

DATA_DIR = Path(__file__).parent / "data"


def _sample(filename: str, n: int = 5) -> list[str]:
    lines = []
    with open(DATA_DIR / filename) as f:
        for line in f:
            if line.strip():
                lines.append(line)
            if len(lines) >= n:
                break
    return lines


def test_detects_json_lines():
    sample = _sample("json_lines.log")
    assert FormatDetector().detect(sample) == LogFormat.JSON_LINES


def test_detects_nginx_combined():
    sample = _sample("nginx_access.log")
    assert FormatDetector().detect(sample) == LogFormat.NGINX_COMBINED


def test_detects_auth_log():
    sample = _sample("auth.log")
    assert FormatDetector().detect(sample) == LogFormat.AUTH_LOG


def test_detects_syslog():
    sample = _sample("syslog.log")
    assert FormatDetector().detect(sample) == LogFormat.SYSLOG


def test_detects_logfmt():
    sample = _sample("logfmt.log")
    assert FormatDetector().detect(sample) == LogFormat.LOGFMT


def test_detects_cef():
    sample = _sample("cef.log")
    assert FormatDetector().detect(sample) == LogFormat.CEF


def test_detects_leef():
    sample = _sample("leef.log")
    assert FormatDetector().detect(sample) == LogFormat.LEEF


def test_syslog_prefixed_cef_still_detected_as_cef():
    # A CEF event wrapped in a syslog prefix must not be mistaken for syslog.
    sample = ["Jan  5 12:00:00 fw01 CEF:0|Vendor|FW|1.0|100|blocked|6|src=10.0.0.1 dst=8.8.8.8"]
    assert FormatDetector().detect(sample) == LogFormat.CEF


def test_prose_with_stray_pair_is_not_logfmt():
    # A sentence that merely contains "x=5" must not be mistaken for logfmt.
    sample = ["the result was x=5 after the computation finished successfully"]
    assert FormatDetector().detect(sample) == LogFormat.PLAINTEXT


def test_empty_sample_returns_plaintext():
    assert FormatDetector().detect([]) == LogFormat.PLAINTEXT
