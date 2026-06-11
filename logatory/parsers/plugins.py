"""Global registry of parsers contributed by plugins.

Built-in parsers are dispatched by the :class:`LogFormat` enum, but a plugin
can't extend an enum.  Instead, plugins register a *named* parser together
with a ``detect`` predicate.  ``FormatDetector`` consults these after all the
built-in checks (just before falling back to plaintext), and ``get_parser``
builds them by name.  Because the registry is module-global, merely loading a
plugin makes its parser available everywhere a format is auto-detected — the
adapters never need a handle to the plugin registry.

This module deliberately depends only on :class:`BaseParser`, so both
``detector`` and ``registry`` can import it without an import cycle.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .base import BaseParser


@dataclass(frozen=True)
class PluginParser:
    """A parser contributed by a plugin.

    ``detect`` inspects a sample of (stripped, non-empty) lines and returns
    True when this parser should handle the source; ``factory`` builds the
    parser instance for a given source name.
    """

    name: str
    detect: Callable[[list[str]], bool]
    factory: Callable[[str], BaseParser]


_PLUGIN_PARSERS: dict[str, PluginParser] = {}


def register_parser(
    name: str,
    detect: Callable[[list[str]], bool],
    factory: Callable[[str], BaseParser],
) -> PluginParser:
    """Register (or replace) a plugin parser keyed by ``name``."""
    parser = PluginParser(name=name, detect=detect, factory=factory)
    _PLUGIN_PARSERS[name] = parser
    return parser


def get_plugin_parser(name: str) -> PluginParser | None:
    """Return the plugin parser registered under ``name``, or None."""
    return _PLUGIN_PARSERS.get(name)


def plugin_parsers() -> list[PluginParser]:
    """Return all registered plugin parsers, in registration order."""
    return list(_PLUGIN_PARSERS.values())
