"""Tests for plugin loader and registry."""

from __future__ import annotations

from pathlib import Path

from logatory.plugins.loader import load_plugins
from logatory.plugins.registry import PluginRegistry

# ---------------------------------------------------------------------------
# PluginRegistry
# ---------------------------------------------------------------------------


class TestPluginRegistry:
    def test_empty_by_default(self) -> None:
        r = PluginRegistry()
        assert r.rules == []
        assert r.rule_dirs == []
        assert r.pii_patterns == []

    def test_add_rule(self) -> None:
        r = PluginRegistry()
        r.add_rule(
            {
                "id": "PLUGIN_RULE",
                "title": "Plugin test rule",
                "level": "high",
                "conditions": [{"field": "message", "op": "contains", "value": "BADWORD"}],
            }
        )
        assert len(r.rules) == 1
        assert r.rules[0].id == "PLUGIN_RULE"

    def test_add_rule_dir(self, tmp_path: Path) -> None:
        r = PluginRegistry()
        r.add_rule_dir(tmp_path)
        assert Path(tmp_path) in r.rule_dirs

    def test_add_rule_dir_string(self, tmp_path: Path) -> None:
        r = PluginRegistry()
        r.add_rule_dir(str(tmp_path))
        assert Path(tmp_path) in r.rule_dirs

    def test_add_pii_pattern(self) -> None:
        r = PluginRegistry()
        r.add_pii_pattern("employee_id", r"EMP-\d{6}", prefix="employee")
        assert len(r.pii_patterns) == 1
        p = r.pii_patterns[0]
        assert p["name"] == "employee_id"
        assert p["prefix"] == "employee"

    def test_add_pii_pattern_default_prefix(self) -> None:
        r = PluginRegistry()
        r.add_pii_pattern("secret", r"SECRET-\w+")
        assert r.pii_patterns[0]["prefix"] == "redacted"

    def test_multiple_rules(self) -> None:
        r = PluginRegistry()
        for i in range(3):
            r.add_rule(
                {
                    "id": f"RULE_{i}",
                    "title": f"Rule {i}",
                    "level": "low",
                    "conditions": [{"field": "message", "op": "contains", "value": str(i)}],
                }
            )
        assert len(r.rules) == 3


# ---------------------------------------------------------------------------
# load_plugins()
# ---------------------------------------------------------------------------


class TestLoadPlugins:
    def test_none_dir_returns_empty_registry(self) -> None:
        registry = load_plugins(None)
        assert registry.rules == []
        assert registry.pii_patterns == []

    def test_nonexistent_dir_returns_empty_registry(self, tmp_path: Path) -> None:
        registry = load_plugins(tmp_path / "does_not_exist")
        assert registry.rules == []

    def test_empty_dir_returns_empty_registry(self, tmp_path: Path) -> None:
        registry = load_plugins(tmp_path)
        assert registry.rules == []

    def test_loads_plugin_with_register_function(self, tmp_path: Path) -> None:
        plugin = tmp_path / "my_plugin.py"
        plugin.write_text(
            "def register(registry):\n"
            "    registry.add_pii_pattern('test_id', r'TEST-\\d+', prefix='test')\n"
        )
        registry = load_plugins(tmp_path)
        assert len(registry.pii_patterns) == 1
        assert registry.pii_patterns[0]["name"] == "test_id"

    def test_plugin_without_register_is_skipped_silently(self, tmp_path: Path) -> None:
        plugin = tmp_path / "no_register.py"
        plugin.write_text("# This plugin has no register() function\nX = 42\n")
        registry = load_plugins(tmp_path)
        assert registry.rules == []

    def test_underscore_files_ignored(self, tmp_path: Path) -> None:
        hidden = tmp_path / "_internal.py"
        hidden.write_text(
            "def register(registry):\n"
            "    registry.add_pii_pattern('hidden', r'HIDDEN', prefix='h')\n"
        )
        registry = load_plugins(tmp_path)
        assert registry.pii_patterns == []

    def test_broken_plugin_does_not_crash_loader(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.py"
        bad.write_text("raise RuntimeError('plugin error')\n")
        # Should not raise — bad plugins are logged and skipped
        registry = load_plugins(tmp_path)
        assert registry.rules == []

    def test_multiple_plugins_all_loaded(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"plugin_{i}.py").write_text(
                f"def register(registry):\n"
                f"    registry.add_pii_pattern('pat_{i}', r'PAT{i}', prefix='p{i}')\n"
            )
        registry = load_plugins(tmp_path)
        assert len(registry.pii_patterns) == 3

    def test_plugin_adds_rule(self, tmp_path: Path) -> None:
        plugin = tmp_path / "rule_plugin.py"
        plugin.write_text(
            "def register(registry):\n"
            "    registry.add_rule({\n"
            "        'id': 'PLUGIN_RULE_01',\n"
            "        'title': 'Plugin Rule',\n"
            "        'level': 'medium',\n"
            "        'conditions': [{'field': 'message', 'op': 'contains', 'value': 'ALERT'}],\n"
            "    })\n"
        )
        registry = load_plugins(tmp_path)
        assert len(registry.rules) == 1
        assert registry.rules[0].id == "PLUGIN_RULE_01"


# ---------------------------------------------------------------------------
# add_parser() — global parser registry integration
# ---------------------------------------------------------------------------


class TestAddParser:
    def test_register_and_introspect(self) -> None:
        from logatory.parsers.base import BaseParser
        from logatory.parsers.plugins import _PLUGIN_PARSERS, get_plugin_parser

        class _Dummy(BaseParser):
            def parse(self, line):  # pragma: no cover - never iterated here
                return None

        r = PluginRegistry()
        try:
            r.add_parser("dummyfmt", lambda lines: False, _Dummy)
            assert len(r.parsers) == 1
            assert r.parsers[0].name == "dummyfmt"
            assert get_plugin_parser("dummyfmt") is not None
        finally:
            _PLUGIN_PARSERS.pop("dummyfmt", None)

    def test_detected_and_built(self) -> None:
        from logatory.models import Event, Severity
        from logatory.parsers.base import BaseParser
        from logatory.parsers.detector import FormatDetector
        from logatory.parsers.plugins import _PLUGIN_PARSERS
        from logatory.parsers.registry import get_parser

        class _PipeParser(BaseParser):
            def parse(self, line):
                if not line.strip():
                    return None
                return Event(raw=line, source=self.source, message=line, severity=Severity.INFO)

        def _detect(lines: list[str]) -> bool:
            return all(line.startswith("PIPE|") for line in lines)

        r = PluginRegistry()
        try:
            r.add_parser("pipefmt", _detect, _PipeParser)

            fmt = FormatDetector().detect(["PIPE|a", "PIPE|b"])
            assert fmt == "pipefmt"

            parser = get_parser(fmt, "src")
            assert isinstance(parser, _PipeParser)
            assert parser.parse("PIPE|hello").message == "PIPE|hello"
        finally:
            _PLUGIN_PARSERS.pop("pipefmt", None)

    def test_builtin_detection_takes_precedence(self) -> None:
        from logatory.parsers.base import BaseParser
        from logatory.parsers.detector import FormatDetector, LogFormat
        from logatory.parsers.plugins import _PLUGIN_PARSERS

        class _Greedy(BaseParser):
            def parse(self, line):  # pragma: no cover - never iterated here
                return None

        r = PluginRegistry()
        try:
            # A greedy plugin that would accept anything must NOT shadow the
            # built-in JSON detection, which runs first.
            r.add_parser("greedy", lambda lines: True, _Greedy)
            fmt = FormatDetector().detect(['{"message": "hi"}'])
            assert fmt == LogFormat.JSON_LINES
        finally:
            _PLUGIN_PARSERS.pop("greedy", None)


# ---------------------------------------------------------------------------
# add_adapter() — global adapter registry integration
# ---------------------------------------------------------------------------


class TestAddAdapter:
    def test_register_and_lookup(self) -> None:
        from logatory.adapters import _REGISTRY, fleet_target_types, get_adapter_class
        from logatory.adapters.base import SourceAdapter

        class _CustomAdapter(SourceAdapter):
            async def events(self):  # pragma: no cover - never iterated here
                return
                yield

        r = PluginRegistry()
        try:
            r.add_adapter("plugin-src", _CustomAdapter)
            assert get_adapter_class("plugin-src") is _CustomAdapter
            assert len(r.adapters) == 1
            assert r.adapters[0].name == "plugin-src"
            # Not a fleet target by default.
            assert "plugin-src" not in fleet_target_types()
        finally:
            _REGISTRY.pop("plugin-src", None)

    def test_fleet_target_opt_in(self) -> None:
        from logatory.adapters import _REGISTRY, fleet_target_types
        from logatory.adapters.base import SourceAdapter

        class _CustomAdapter(SourceAdapter):
            async def events(self):  # pragma: no cover - never iterated here
                return
                yield

        r = PluginRegistry()
        try:
            r.add_adapter("fleet-src", _CustomAdapter, fleet_target=True)
            assert "fleet-src" in fleet_target_types()
        finally:
            _REGISTRY.pop("fleet-src", None)

    def test_loaded_from_plugin_file(self, tmp_path: Path) -> None:
        from logatory.adapters import _REGISTRY, get_adapter_class

        plugin = tmp_path / "adapter_plugin.py"
        plugin.write_text(
            "from logatory.adapters.base import SourceAdapter\n"
            "\n"
            "class MyAdapter(SourceAdapter):\n"
            "    async def events(self):\n"
            "        return\n"
            "        yield\n"
            "\n"
            "def register(registry):\n"
            "    registry.add_adapter('from-file', MyAdapter)\n"
        )
        try:
            registry = load_plugins(tmp_path)
            assert len(registry.adapters) == 1
            assert get_adapter_class("from-file") is not None
        finally:
            _REGISTRY.pop("from-file", None)


# ---------------------------------------------------------------------------
# The shipped example plugin (plugins/example_plugin.py)
# ---------------------------------------------------------------------------


class TestExamplePlugin:
    def test_example_plugin_registers_everything(self) -> None:
        from logatory.adapters import _REGISTRY, get_adapter_class
        from logatory.parsers.plugins import _PLUGIN_PARSERS, get_plugin_parser

        plugins_dir = Path(__file__).parent.parent / "plugins"
        try:
            registry = load_plugins(plugins_dir)

            # rule + PII pattern collected on the registry
            assert any(r.id == "CUSTOM_EXAMPLE" for r in registry.rules)
            assert any(p["name"] == "employee_id" for p in registry.pii_patterns)

            # parser + adapter registered into the global registries
            assert get_plugin_parser("appliance") is not None
            assert get_adapter_class("demo-source") is not None

            # the example parser actually parses an APP| line
            parser = get_plugin_parser("appliance").factory("src")
            ev = parser.parse("APP|2026-06-13T08:15:04Z|ERROR|auth|login failed for user")
            assert ev is not None
            assert ev.message == "login failed for user"
            assert ev.severity.value == "error"
            assert ev.parsed_fields["component"] == "auth"
            assert parser.parse("not an app line") is None
        finally:
            _PLUGIN_PARSERS.pop("appliance", None)
            _REGISTRY.pop("demo-source", None)
