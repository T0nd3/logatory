"""Example Logatory plugin — custom rule, PII pattern, parser and adapter.

A plugin is just a Python file with a top-level ``register(registry)`` function.
Logatory imports every ``*.py`` file in your ``plugins_dir`` (files starting with
``_`` are skipped) and calls ``register`` once at startup.

Enable this plugin by setting in config.yaml:

    plugins_dir: plugins/

Then verify with:  logatory rules list      (shows CUSTOM_EXAMPLE)

See docs/PLUGINS.md for the full plugin guide.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime

from logatory.adapters.base import SourceAdapter
from logatory.models import Event, Severity
from logatory.parsers.base import BaseParser

# ──────────────────────────────────────────────────────────────────────────
# A custom parser for a fictional appliance log, e.g.:
#   APP|2026-06-13T08:15:04Z|ERROR|auth|login failed for user
# ──────────────────────────────────────────────────────────────────────────

_LEVELS = {
    "DEBUG": Severity.DEBUG,
    "INFO": Severity.INFO,
    "WARN": Severity.WARNING,
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "CRIT": Severity.CRITICAL,
    "CRITICAL": Severity.CRITICAL,
}


class ApplianceParser(BaseParser):
    """Parse pipe-delimited 'APP|<ts>|<level>|<component>|<message>' lines."""

    def parse(self, line: str) -> Event | None:
        stripped = line.strip()
        if not stripped.startswith("APP|"):
            return None
        parts = stripped.split("|", 4)
        if len(parts) < 5:
            return None
        _, ts_raw, level, component, message = parts
        try:
            timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except ValueError:
            timestamp = None
        return Event(
            raw=stripped,
            source=self.source,
            message=message,
            timestamp=timestamp,
            severity=_LEVELS.get(level.upper(), Severity.INFO),
            parsed_fields={"component": component, "level": level},
        )


def _detect_appliance(sample_lines: list[str]) -> bool:
    """Auto-detect: every sampled line carries the APP| marker."""
    return bool(sample_lines) and all(line.startswith("APP|") for line in sample_lines)


# ──────────────────────────────────────────────────────────────────────────
# A minimal custom adapter — a template you can adapt to a real source.
# Adapters yield normalized Event objects via async iteration.
# ──────────────────────────────────────────────────────────────────────────


class DemoAdapter(SourceAdapter):
    """Yield a couple of synthetic events. Replace events() with real I/O."""

    def __init__(self, source: str = "demo") -> None:
        self.source = source

    async def events(self) -> AsyncIterator[Event]:
        for level, msg in (("INFO", "demo adapter started"), ("ERROR", "demo failure")):
            yield Event(
                raw=f"{level} {msg}",
                source=self.source,
                message=msg,
                severity=_LEVELS.get(level, Severity.INFO),
            )


def register(registry) -> None:
    """Called once at startup. Contribute rules, PII patterns, parsers, adapters."""

    # ── Custom detection rule (same schema as built-in YAML rules) ─────────
    registry.add_rule(
        {
            "id": "CUSTOM_EXAMPLE",
            "title": "Example: custom trigger word",
            "description": "Fires when the message contains 'EXAMPLE_TRIGGER'.",
            "level": "medium",
            "detection": {
                "match": [
                    {"field": "message", "op": "contains", "value": "EXAMPLE_TRIGGER"},
                ]
            },
        }
    )

    # ── Custom PII pattern → redacts EMP-1234 as <employee_…> ──────────────
    registry.add_pii_pattern(name="employee_id", pattern=r"\bEMP-\d{4,8}\b", prefix="employee")

    # ── Custom log-format parser (auto-detected everywhere) ────────────────
    registry.add_parser("appliance", detect=_detect_appliance, factory=ApplianceParser)

    # ── Custom source adapter (looked up by name like a built-in source) ───
    registry.add_adapter("demo-source", DemoAdapter)

    # Uncomment to load an entire directory of YAML rule files:
    # from pathlib import Path
    # registry.add_rule_dir(Path(__file__).parent / "my_rules")
