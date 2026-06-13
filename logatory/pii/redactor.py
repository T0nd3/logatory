from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

import yaml

from .patterns import BUILTIN_PATTERNS, PIIPattern


class RedactMode(str, Enum):
    REDACT = "redact"  # replace with deterministic hash → correlation preserved
    MASK = "mask"  # replace with <TYPE> → maximum anonymity, no correlation
    DRY_RUN = "dry_run"  # show what would be redacted, make no changes


@dataclass
class RedactionResult:
    text: str
    hits: list[tuple[str, str]]  # [(matched_value, replacement), ...]


class PIIRedactor:
    def __init__(
        self,
        salt: str,
        extra_patterns: list[PIIPattern] | None = None,
        mode: RedactMode = RedactMode.REDACT,
    ) -> None:
        self._salt = salt.encode() if salt else b"default-dev-salt-change-me"
        self._patterns = BUILTIN_PATTERNS + (extra_patterns or [])
        self.mode = mode

    @classmethod
    def from_config(
        cls,
        salt: str,
        rules_path: Path,
        mode: RedactMode = RedactMode.REDACT,
        additional: list[PIIPattern] | None = None,
    ) -> PIIRedactor:
        extra: list[PIIPattern] = []
        if rules_path.exists():
            with rules_path.open() as f:
                data = yaml.safe_load(f) or {}
            extra.extend(
                PIIPattern(
                    name=rule["name"],
                    pattern=re.compile(rule["pattern"]),
                    prefix=rule.get("prefix", rule["name"]),
                )
                for rule in data.get("patterns", [])
            )
        if additional:
            extra.extend(additional)
        return cls(salt=salt, extra_patterns=extra or None, mode=mode)

    def redact(self, text: str) -> RedactionResult:
        hits: list[tuple[str, str]] = []
        result = text

        for pii in self._patterns:

            def replace(m: re.Match, pii=pii) -> str:
                value = m.group()
                if pii.name == "credit_card" and not _luhn_check(value):
                    return value
                replacement = self._replacement(value, pii.prefix)
                hits.append((value, replacement))
                return replacement

            result = pii.pattern.sub(replace, result)

        return RedactionResult(text=result, hits=hits)

    def _replacement(self, value: str, prefix: str) -> str:
        # DRY_RUN: keep the original text intact — only the hit is recorded.
        # Callers use len(result.hits) to count what *would* be redacted.
        if self.mode == RedactMode.DRY_RUN:
            return value
        if self.mode == RedactMode.MASK:
            return f"<{prefix.upper()}>"
        h = hmac.new(self._salt, value.encode(), hashlib.sha256).hexdigest()[:8]
        return f"{prefix}_{h}"


def _luhn_check(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
