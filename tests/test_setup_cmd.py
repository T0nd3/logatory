"""Tests for `logatory init` (and `logatory doctor`)."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from logatory.cli.main import app as main_app
from logatory.config import Config

runner = CliRunner()


def _salt_of(path: Path) -> str:
    return yaml.safe_load(path.read_text())["pii_salt"]


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_init_creates_loadable_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    res = runner.invoke(main_app, ["init"])
    assert res.exit_code == 0, res.output
    target = tmp_path / "config.yaml"
    assert target.exists()
    # generated salt is a 32-char hex string
    salt = _salt_of(target)
    assert len(salt) == 32
    # the file loads cleanly through Config
    cfg = Config.load(target)
    assert cfg.pii_salt == salt
    assert cfg.llm.provider == "ollama"


def test_init_refuses_overwrite_without_force(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("db_path: keep.db\n")
    res = runner.invoke(main_app, ["init"])
    assert res.exit_code == 1
    assert "already exists" in res.output
    # untouched
    assert "keep.db" in (tmp_path / "config.yaml").read_text()


def test_init_force_overwrites(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("db_path: old.db\n")
    res = runner.invoke(main_app, ["init", "--force"])
    assert res.exit_code == 0
    assert "pii_salt" in (tmp_path / "config.yaml").read_text()


def test_init_minimal(tmp_path):
    target = tmp_path / "c.yaml"
    res = runner.invoke(main_app, ["init", "-o", str(target), "--minimal"])
    assert res.exit_code == 0
    data = yaml.safe_load(target.read_text())
    assert data["db_path"] == "logatory.db"
    assert len(data["pii_salt"]) == 32
    assert "alerts" not in data  # minimal omits the optional sections


def test_init_output_creates_parent_dirs(tmp_path):
    target = tmp_path / "nested" / "dir" / "config.yaml"
    res = runner.invoke(main_app, ["init", "-o", str(target)])
    assert res.exit_code == 0
    assert target.exists()


def test_init_generates_unique_salt(tmp_path):
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"
    runner.invoke(main_app, ["init", "-o", str(a)])
    runner.invoke(main_app, ["init", "-o", str(b)])
    assert _salt_of(a) != _salt_of(b)


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


class _FakeLLM:
    def __init__(self, *, cloud: bool = False, available: bool = True) -> None:
        self.is_cloud = cloud
        self.provider_name = "fake"
        self._available = available

    def is_available(self) -> bool:
        return self._available


def _patch_llm(monkeypatch, **kwargs) -> None:
    # doctor imports make_llm_client from logatory.llm.factory at call time.
    monkeypatch.setattr("logatory.llm.factory.make_llm_client", lambda _cfg: _FakeLLM(**kwargs))


def _cfg(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_doctor_healthy_local(tmp_path, monkeypatch):
    _patch_llm(monkeypatch, cloud=False, available=True)
    cfg = _cfg(
        tmp_path,
        f"db_path: {tmp_path / 'l.db'}\npii_salt: abc123\n"
        "llm:\n  provider: ollama\n  model: gemma3:4b\n",
    )
    res = runner.invoke(main_app, ["doctor", "--config", str(cfg)])
    assert res.exit_code == 0, res.output
    assert "All critical checks passed" in res.output
    assert "PII salt" in res.output


def test_doctor_warns_empty_salt_but_passes(tmp_path, monkeypatch):
    _patch_llm(monkeypatch, cloud=False, available=True)
    cfg = _cfg(tmp_path, f"db_path: {tmp_path / 'l.db'}\npii_salt: ''\n")
    res = runner.invoke(main_app, ["doctor", "--config", str(cfg)])
    assert res.exit_code == 0, res.output
    assert "WARN" in res.output


def test_doctor_fails_on_invalid_alerts(tmp_path, monkeypatch):
    _patch_llm(monkeypatch, cloud=False, available=True)
    cfg = _cfg(
        tmp_path,
        f"db_path: {tmp_path / 'l.db'}\npii_salt: abc\nalerts:\n  - type: slack\n",  # missing url
    )
    res = runner.invoke(main_app, ["doctor", "--config", str(cfg)])
    assert res.exit_code == 1
    assert "FAIL" in res.output


def test_doctor_fails_cloud_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _patch_llm(monkeypatch, cloud=True, available=False)
    cfg = _cfg(
        tmp_path,
        f"db_path: {tmp_path / 'l.db'}\npii_salt: abc\nllm:\n  provider: claude\n  model: x\n",
    )
    res = runner.invoke(main_app, ["doctor", "--config", str(cfg)])
    assert res.exit_code == 1
    assert "no API key" in res.output


def test_doctor_warns_unexpanded_alert_env(tmp_path, monkeypatch):
    monkeypatch.delenv("SOME_UNSET_HOOK", raising=False)
    _patch_llm(monkeypatch, cloud=False, available=True)
    cfg = _cfg(
        tmp_path,
        f"db_path: {tmp_path / 'l.db'}\npii_salt: abc\n"
        "alerts:\n  - type: slack\n    url: ${SOME_UNSET_HOOK}\n",
    )
    res = runner.invoke(main_app, ["doctor", "--config", str(cfg)])
    # channel builds fine (url is a non-empty string), but env var is unset
    assert res.exit_code == 0, res.output
    assert "unset env var" in res.output
