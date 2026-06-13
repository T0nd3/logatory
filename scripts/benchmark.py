#!/usr/bin/env python3
"""Throughput benchmark for the Logatory processing pipeline.

Generates synthetic JSON log lines and pushes them through the same three stages
every scan performs — parse, PII-redact, run the rule engine — then reports how
many lines per second the pipeline sustains. Useful for spotting performance
regressions; ``run_benchmark`` is importable so tests can exercise it cheaply.

    python scripts/benchmark.py --lines 100000
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from types import SimpleNamespace

from logatory.parsers.detector import FormatDetector
from logatory.parsers.registry import get_parser
from logatory.pii.redactor import PIIRedactor
from logatory.rules.loader import build_engine

_LEVELS = ("info", "info", "info", "warning", "error")


def generate_lines(n: int) -> list[str]:
    """Build *n* synthetic JSON log lines carrying PII and an occasional trigger."""
    lines = []
    for i in range(n):
        msg = (
            f"request from 10.0.{i % 256}.{(i * 7) % 256} "
            f"user user{i}@example.com EMP-{1000 + i % 9000} "
            f"processed in {i % 500}ms"
        )
        if i % 50 == 0:
            msg += " EXAMPLE_TRIGGER failed"
        lines.append(
            json.dumps(
                {
                    "timestamp": "2026-06-13T08:15:04Z",
                    "level": _LEVELS[i % len(_LEVELS)],
                    "message": msg,
                }
            )
        )
    return lines


def run_benchmark(n: int = 50_000) -> dict:
    """Run the pipeline over *n* generated lines and return throughput metrics."""
    lines = generate_lines(n)

    # No PII rules file → built-in patterns only. No plugins.
    redactor = PIIRedactor.from_config(salt="benchmark", rules_path=Path("__no_such_file__"))
    registry = SimpleNamespace(rule_dirs=[], rules=[])
    engine = build_engine(False, None, registry)
    parser = get_parser(FormatDetector().detect(lines[:5]), "benchmark")

    events = findings = pii_hits = 0
    start = time.perf_counter()
    for line in lines:
        event = parser.parse(line)
        if event is None:
            continue
        result = redactor.redact(event.message)
        event.message = result.text
        event.raw = redactor.redact(event.raw).text
        pii_hits += len(result.hits)
        events += 1
        if engine:
            findings += len(engine.process(event))
    elapsed = time.perf_counter() - start

    return {
        "lines": n,
        "events": events,
        "findings": findings,
        "pii_hits": pii_hits,
        "elapsed_s": round(elapsed, 4),
        "lines_per_s": round(n / elapsed) if elapsed > 0 else 0,
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Logatory pipeline throughput benchmark.")
    p.add_argument("--lines", type=int, default=50_000, help="Number of lines to process.")
    args = p.parse_args()

    print(f"Benchmarking {args.lines:,} lines through parse + redact + rules ...")
    m = run_benchmark(args.lines)
    print(f"  Elapsed     : {m['elapsed_s']:.3f}s")
    print(f"  Throughput  : {m['lines_per_s']:,} lines/s")
    print(f"  Events      : {m['events']:,}")
    print(f"  PII hits    : {m['pii_hits']:,}")
    print(f"  Findings    : {m['findings']:,}")


if __name__ == "__main__":
    main()
