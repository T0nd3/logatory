"""Tests for configuration loading and auto-discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from logatory.config import Config


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Isolate config discovery: empty cwd, empty fake HOME, no env override."""
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.delenv("LOGATORY_CONFIG", raising=False)
    return cwd, home


def _write(path: Path, body: str = "db_path: discovered.db\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# find_config_path
# ---------------------------------------------------------------------------


def test_find_returns_none_when_nothing(isolated_env):
    assert Config.find_config_path() is None


def test_find_cwd_config(isolated_env):
    cwd, _ = isolated_env
    _write(cwd / "config.yaml")
    assert Config.find_config_path() == Path("config.yaml")


def test_find_home_config(isolated_env):
    _, home = isolated_env
    target = _write(home / ".config" / "logatory" / "config.yaml")
    assert Config.find_config_path() == target


def test_env_var_wins(isolated_env, monkeypatch):
    cwd, _ = isolated_env
    env_cfg = _write(cwd / "custom.yaml")
    _write(cwd / "config.yaml")  # also present, but env should win
    monkeypatch.setenv("LOGATORY_CONFIG", str(env_cfg))
    assert Config.find_config_path() == env_cfg


def test_cwd_beats_home(isolated_env):
    cwd, home = isolated_env
    _write(cwd / "config.yaml")
    _write(home / ".config" / "logatory" / "config.yaml")
    assert Config.find_config_path() == Path("config.yaml")


def test_missing_env_path_is_skipped(isolated_env, monkeypatch):
    cwd, _ = isolated_env
    monkeypatch.setenv("LOGATORY_CONFIG", str(cwd / "does_not_exist.yaml"))
    home_cfg = _write(isolated_env[1] / ".config" / "logatory" / "config.yaml")
    # env path doesn't exist → falls through to the home config
    assert Config.find_config_path() == home_cfg


# ---------------------------------------------------------------------------
# load() integration
# ---------------------------------------------------------------------------


def test_load_none_uses_discovered_config(isolated_env):
    cwd, _ = isolated_env
    _write(cwd / "config.yaml", "db_path: from_cwd.db\n")
    cfg = Config.load()
    assert cfg.db_path == Path("from_cwd.db")


def test_load_none_defaults_when_nothing_found(isolated_env):
    cfg = Config.load()
    assert cfg.db_path == Path("logatory.db")  # built-in default


def test_load_explicit_path_ignores_discovery(isolated_env, tmp_path):
    cwd, _ = isolated_env
    _write(cwd / "config.yaml", "db_path: from_cwd.db\n")  # would be discovered
    explicit = _write(tmp_path / "explicit.yaml", "db_path: explicit.db\n")
    cfg = Config.load(explicit)
    assert cfg.db_path == Path("explicit.db")
