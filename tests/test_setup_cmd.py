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
