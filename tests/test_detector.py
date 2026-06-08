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


def test_empty_sample_returns_plaintext():
    assert FormatDetector().detect([]) == LogFormat.PLAINTEXT
