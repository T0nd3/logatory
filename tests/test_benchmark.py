"""Smoke test for the performance benchmark script (scripts/benchmark.py).

This guards the benchmark harness itself (so it keeps running as the pipeline
evolves); it deliberately makes no wall-clock assertions, which would be flaky.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_BENCH_PATH = Path(__file__).parent.parent / "scripts" / "benchmark.py"


def _load_benchmark():
    spec = importlib.util.spec_from_file_location("benchmark", _BENCH_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generate_lines_count():
    bench = _load_benchmark()
    lines = bench.generate_lines(10)
    assert len(lines) == 10
    # every line is valid JSON with a message
    import json

    assert all("message" in json.loads(line) for line in lines)


def test_run_benchmark_returns_sane_metrics():
    bench = _load_benchmark()
    m = bench.run_benchmark(200)
    assert m["lines"] == 200
    assert m["events"] == 200  # all synthetic JSON lines parse
    assert m["pii_hits"] > 0  # emails + IPs are redacted
    assert m["lines_per_s"] > 0
    assert m["elapsed_s"] >= 0
    assert m["findings"] >= 0
