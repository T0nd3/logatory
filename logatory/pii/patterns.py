"""Built-in PII detection patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PIIPattern:
    name: str
    pattern: re.Pattern
    prefix: str  # prefix used in the pseudonymized replacement


BUILTIN_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        name="email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        prefix="email",
    ),
    PIIPattern(
        name="ipv4",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        prefix="ip",
    ),
    PIIPattern(
        name="ipv6",
        pattern=re.compile(
            # Anchored with lookaround instead of \b because ':' is not a word char.
            r"(?<![:\da-fA-F])"
            r"(?:"
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"  # full: a:b:c:d:e:f:g:h
            r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"  # trailing ::  e.g. fe80::
            r"|:(?::[0-9a-fA-F]{1,4}){1,7}"  # leading ::   e.g. ::1, ::ffff:x
            r"|(?:[0-9a-fA-F]{1,4}:)+(?::[0-9a-fA-F]{1,4})+"  # middle ::  e.g. 2001:db8::1
            r")"
            r"(?![:\da-fA-F])",
        ),
        prefix="ip",
    ),
    PIIPattern(
        name="phone_de",
        # German numbers: +49 / 0049 / national 0, then 7-15 digits with
        # optional space/dash/slash separators *between* digits. Counting only
        # real digits (not separators) toward the length keeps it from matching
        # date/time fragments like "06-07 08" inside "2026-06-07 08:15:04".
        pattern=re.compile(r"(?<!\w)(?:\+49|0049|0)[\s/\-]?\d(?:[\s/\-]?\d){6,14}(?!\w)"),
        prefix="phone",
    ),
    PIIPattern(
        name="iban",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
        prefix="iban",
    ),
    PIIPattern(
        name="credit_card",
        # 13-19 digit sequences with optional separators; validated via Luhn in redactor
        pattern=re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
        prefix="card",
    ),
]
