"""Plugin registry — collects rules and PII patterns contributed by plugins."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from logatory.rules.model import Rule

if TYPE_CHECKING:
    from logatory.adapters import AdapterSpec
    from logatory.adapters.base import SourceAdapter
    from logatory.parsers.base import BaseParser
    from logatory.parsers.plugins import PluginParser


@dataclass
class PluginRegistry:
    """Accumulates contributions from all loaded plugins.

    Plugin authors call the ``add_*`` methods inside their ``register()``
    function; the host application then reads the collected lists.

    Rules and PII patterns use a *collect-and-pass* model: they are gathered
    here and handed to the engine/redactor by whichever CLI entrypoint wired
    up the registry.  Parsers and adapters can't work that way — they are
    resolved through module-global lookups (``FormatDetector`` / the adapter
    registry) far from any registry handle — so ``add_parser`` and
    ``add_adapter`` register into those global registries immediately, and
    only keep a copy here for introspection.
    """

    #: Rules loaded from inline dicts (same schema as built-in YAML rules).
    rules: list[Rule] = field(default_factory=list)
    #: Extra YAML rule directories contributed by plugins.
    rule_dirs: list[Path] = field(default_factory=list)
    #: Extra PII pattern dicts ({name, pattern, prefix}).
    pii_patterns: list[dict] = field(default_factory=list)
    #: Parsers registered into the global parser registry (for introspection).
    parsers: list[PluginParser] = field(default_factory=list)
    #: Adapters registered into the global adapter registry (for introspection).
    adapters: list[AdapterSpec] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Public plugin API
    # ------------------------------------------------------------------

    def add_rule(self, data: dict) -> None:
        """Register a rule from a dict (same schema as YAML rule files).

        Required keys: ``id``, ``title``, ``level``.
        Detection conditions go under ``detection.match``.

        Example::

            registry.add_rule({
                "id": "MY_RULE",
                "title": "My custom rule",
                "level": "high",
                "detection": {
                    "match": [{"field": "message", "op": "contains", "value": "BADWORD"}]
                },
            })
        """
        from logatory.rules.loader import rule_from_dict

        rule = rule_from_dict(data, source_file="<plugin>")
        self.rules.append(rule)

    def add_rule_dir(self, path: Path | str) -> None:
        """Register a directory of YAML rule files to be loaded."""
        self.rule_dirs.append(Path(path))

    def add_pii_pattern(self, name: str, pattern: str, prefix: str = "redacted") -> None:
        """Register a custom PII regex pattern.

        Args:
            name:    Unique name (e.g. "employee_id").
            pattern: Python regex string.
            prefix:  Replacement prefix (e.g. "employee" → ``<employee_XYZ>``).
        """
        self.pii_patterns.append({"name": name, "pattern": pattern, "prefix": prefix})

    def add_parser(
        self,
        name: str,
        detect: Callable[[list[str]], bool],
        factory: Callable[[str], BaseParser],
    ) -> None:
        """Register a custom log-format parser.

        The parser is added to the global parser registry straight away, so
        format auto-detection picks it up everywhere.  ``detect`` receives a
        sample of stripped, non-empty lines and returns True when this parser
        should handle them; it runs after all built-in format checks, just
        before the plaintext fallback.  ``factory`` builds the parser for a
        given source name.

        Args:
            name:    Unique format name (e.g. "cef").
            detect:  ``(sample_lines) -> bool`` predicate for auto-detection.
            factory: ``(source) -> BaseParser`` builder.
        """
        from logatory.parsers.plugins import register_parser

        self.parsers.append(register_parser(name, detect, factory))

    def add_adapter(
        self,
        name: str,
        adapter_cls: type[SourceAdapter],
        fleet_target: bool = False,
    ) -> None:
        """Register a custom source adapter.

        The adapter is added to the global adapter registry straight away, so
        it can be looked up by name like any built-in source.

        Args:
            name:         Unique source name (e.g. "kafka").
            adapter_cls:  A :class:`SourceAdapter` subclass.
            fleet_target: Whether the adapter is usable as a per-host fleet
                          target.  Defaults to False — plugin authors must opt
                          in (and provide a fleet builder) before exposing it
                          to fleet target files.
        """
        from logatory.adapters import AdapterSpec, register_adapter

        spec = AdapterSpec(name=name, adapter_cls=adapter_cls, fleet_target=fleet_target)
        register_adapter(spec)
        self.adapters.append(spec)
