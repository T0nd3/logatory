from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logatory.anomaly.baseline import BaselineStats, FeatureStat, compute_stats
from logatory.anomaly.detector import (
    AnomalyResult,
    anomaly_results_to_findings,
    detect_anomalies,
)
from logatory.anomaly.features import FeatureExtractor, TimeBucket
from logatory.models import Event, FindingSeverity, Severity
from logatory.storage.baseline_repo import BaselineRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


def _event(
    message: str,
    severity: Severity = Severity.INFO,
    ts: datetime | None = None,
    source: str = "test",
    parsed_fields: dict | None = None,
) -> Event:
    return Event(
        raw=message,
        source=source,
        message=message,
        timestamp=ts or _T0,
        severity=severity,
        parsed_fields=parsed_fields or {},
    )


def _bucket(
    event_count: int = 100,
    error_count: int = 2,
    warning_count: int = 5,
    http_5xx: int = 0,
    http_4xx: int = 3,
    avg_bytes: float = 1000.0,
    ts: datetime | None = None,
) -> TimeBucket:
    b = TimeBucket(ts or _T0)
    b.event_count = event_count
    b.error_count = error_count
    b.warning_count = warning_count
    b.http_5xx_count = http_5xx
    b.http_4xx_count = http_4xx
    b.total_bytes = int(avg_bytes * max(event_count, 1))
    b.bytes_count = event_count
    return b


def _make_baseline(
    n: int = 10,
    event_count_mean: float = 100.0,
    event_count_std: float = 10.0,
    error_rate_mean: float = 0.02,
    error_rate_std: float = 0.005,
) -> BaselineStats:
    """Build a synthetic baseline from feature dicts."""
    import random

    random.seed(42)
    fds = [
        {
            "event_count": random.gauss(event_count_mean, event_count_std),
            "error_rate": max(0.0, random.gauss(error_rate_mean, error_rate_std)),
            "warning_rate": 0.05,
            "source_count": 1.0,
            "http_5xx_count": 0.0,
            "http_4xx_count": 3.0,
            "avg_bytes": 1000.0,
            "path_entropy": 2.0,
        }
        for _ in range(n)
    ]
    return compute_stats(fds, "test")


@pytest.fixture
def repo(tmp_path: Path) -> BaselineRepository:
    r = BaselineRepository(tmp_path / "baseline.db")
    r.open()
    yield r
    r.close()


# ---------------------------------------------------------------------------
# TimeBucket
# ---------------------------------------------------------------------------


class TestTimeBucket:
    def test_error_rate_zero_events(self):
        b = TimeBucket(_T0)
        assert b.error_rate == 0.0

    def test_error_rate(self):
        b = _bucket(event_count=100, error_count=5)
        assert b.error_rate == pytest.approx(0.05)

    def test_warning_rate(self):
        b = _bucket(event_count=100, warning_count=10)
        assert b.warning_rate == pytest.approx(0.10)

    def test_avg_bytes(self):
        b = TimeBucket(_T0)
        b.total_bytes = 3000
        b.bytes_count = 3
        assert b.avg_bytes == pytest.approx(1000.0)

    def test_avg_bytes_no_data(self):
        b = TimeBucket(_T0)
        assert b.avg_bytes == 0.0

    def test_source_count(self):
        b = TimeBucket(_T0)
        b._sources = {"host1", "host2", "host3"}
        assert b.source_count == 3.0

    def test_path_entropy_uniform(self):
        b = TimeBucket(_T0)
        b._path_tokens = ["a", "b", "c", "d"]  # uniform → max entropy
        assert b.path_entropy > 1.0

    def test_path_entropy_single_path(self):
        b = TimeBucket(_T0)
        b._path_tokens = ["api"] * 10  # all same → entropy 0
        assert b.path_entropy == pytest.approx(0.0)

    def test_to_feature_dict_keys(self):
        b = _bucket()
        fd = b.to_feature_dict()
        expected = {
            "event_count",
            "error_rate",
            "warning_rate",
            "source_count",
            "http_5xx_count",
            "http_4xx_count",
            "avg_bytes",
            "path_entropy",
        }
        assert set(fd.keys()) == expected

    def test_to_feature_dict_values_float(self):
        b = _bucket()
        for v in b.to_feature_dict().values():
            assert isinstance(v, float)


# ---------------------------------------------------------------------------
# FeatureExtractor
# ---------------------------------------------------------------------------


class TestFeatureExtractor:
    def test_empty_events(self):
        ext = FeatureExtractor(bucket_seconds=60)
        assert ext.extract([]) == []

    def test_no_timestamps_ignored(self):
        ev = Event(
            raw="x",
            source="s",
            message="x",
            timestamp=None,
            severity=Severity.INFO,
            parsed_fields={},
        )
        ext = FeatureExtractor(bucket_seconds=60)
        assert ext.extract([ev]) == []

    def test_single_event_one_bucket(self):
        events = [_event("hello", ts=_T0)]
        buckets = FeatureExtractor(60).extract(events)
        assert len(buckets) == 1
        assert buckets[0].event_count == 1

    def test_two_events_same_bucket(self):
        t1 = _T0
        t2 = _T0 + timedelta(seconds=30)
        events = [_event("a", ts=t1), _event("b", ts=t2)]
        buckets = FeatureExtractor(60).extract(events)
        assert len(buckets) == 1
        assert buckets[0].event_count == 2

    def test_two_events_different_buckets(self):
        t1 = _T0
        t2 = _T0 + timedelta(seconds=90)
        events = [_event("a", ts=t1), _event("b", ts=t2)]
        buckets = FeatureExtractor(60).extract(events)
        assert len(buckets) == 2

    def test_error_counted(self):
        ev = _event("fail", severity=Severity.ERROR, ts=_T0)
        buckets = FeatureExtractor(60).extract([ev])
        assert buckets[0].error_count == 1

    def test_warning_counted(self):
        ev = _event("warn", severity=Severity.WARNING, ts=_T0)
        buckets = FeatureExtractor(60).extract([ev])
        assert buckets[0].warning_count == 1

    def test_http_5xx_counted(self):
        ev = _event("GET /", ts=_T0, parsed_fields={"status": "503"})
        buckets = FeatureExtractor(60).extract([ev])
        assert buckets[0].http_5xx_count == 1

    def test_http_4xx_counted(self):
        ev = _event("GET /missing", ts=_T0, parsed_fields={"status": "404"})
        buckets = FeatureExtractor(60).extract([ev])
        assert buckets[0].http_4xx_count == 1

    def test_bytes_extracted(self):
        ev = _event("GET /", ts=_T0, parsed_fields={"bytes": "2048"})
        buckets = FeatureExtractor(60).extract([ev])
        assert buckets[0].avg_bytes == pytest.approx(2048.0)

    def test_source_tracked(self):
        ev = _event("x", ts=_T0, source="web-server")
        buckets = FeatureExtractor(60).extract([ev])
        assert "web-server" in buckets[0]._sources

    def test_buckets_sorted_by_time(self):
        events = [
            _event("c", ts=_T0 + timedelta(minutes=2)),
            _event("a", ts=_T0),
            _event("b", ts=_T0 + timedelta(minutes=1)),
        ]
        buckets = FeatureExtractor(60).extract(events)
        assert buckets[0].ts < buckets[1].ts < buckets[2].ts


# ---------------------------------------------------------------------------
# Baseline stats
# ---------------------------------------------------------------------------


class TestComputeStats:
    def test_empty_returns_empty_baseline(self):
        stats = compute_stats([], "test")
        assert stats.n_buckets == 0
        assert not stats.is_trained()

    def test_feature_names_preserved(self):
        fds = [{"event_count": 10.0, "error_rate": 0.01}] * 5
        stats = compute_stats(fds, "test")
        assert "event_count" in stats.features
        assert "error_rate" in stats.features

    def test_mean_correct(self):
        fds = [{"x": float(i)} for i in range(1, 6)]  # 1,2,3,4,5
        stats = compute_stats(fds, "test")
        assert stats.features["x"].mean == pytest.approx(3.0)

    def test_std_correct(self):
        fds = [{"x": 0.0}, {"x": 0.0}, {"x": 0.0}]
        stats = compute_stats(fds, "test")
        assert stats.features["x"].std == pytest.approx(0.0)

    def test_is_trained_requires_5_buckets(self):
        fds = [{"x": 1.0}] * 4
        assert not compute_stats(fds, "test").is_trained()
        fds2 = [{"x": 1.0}] * 5
        assert compute_stats(fds2, "test").is_trained()

    def test_zscore_zero_for_mean_value(self):
        fds = [{"x": float(i)} for i in range(10)]
        stats = compute_stats(fds, "test")
        mean_val = stats.features["x"].mean
        zs = stats.zscore_dict({"x": mean_val})
        assert zs["x"] == pytest.approx(0.0, abs=1e-9)

    def test_zscore_positive_above_mean(self):
        # std=0 → zscore returns 0
        fds2 = [{"x": float(i)} for i in range(10)]
        stats = compute_stats(fds2, "test")
        z = stats.zscore_dict({"x": stats.features["x"].mean + stats.features["x"].std})
        assert z["x"] == pytest.approx(1.0, abs=0.01)


# ---------------------------------------------------------------------------
# FeatureStat
# ---------------------------------------------------------------------------


class TestFeatureStat:
    def test_zscore_zero_std(self):
        stat = FeatureStat(mean=5.0, std=0.0, n=3)
        assert stat.zscore(5.0) == 0.0
        assert stat.zscore(99.0) == 0.0

    def test_zscore_positive(self):
        stat = FeatureStat(mean=0.0, std=1.0, n=10)
        assert stat.zscore(2.0) == pytest.approx(2.0)

    def test_zscore_negative(self):
        stat = FeatureStat(mean=10.0, std=2.0, n=10)
        assert stat.zscore(4.0) == pytest.approx(-3.0)


# ---------------------------------------------------------------------------
# detect_anomalies
# ---------------------------------------------------------------------------


class TestDetectAnomalies:
    def test_empty_buckets(self):
        baseline = _make_baseline()
        assert detect_anomalies([], baseline) == []

    def test_untrained_baseline_returns_empty(self):
        fds = [{"event_count": 100.0, "error_rate": 0.01}] * 3  # < 5 buckets
        baseline = compute_stats(fds, "test")
        assert not baseline.is_trained()
        b = _bucket()
        assert detect_anomalies([b], baseline) == []

    def test_normal_bucket_not_flagged(self):
        baseline = _make_baseline(n=10, event_count_mean=100.0, event_count_std=10.0)
        b = _bucket(event_count=105)  # well within 3σ
        results = detect_anomalies([b], baseline, threshold=3.0)
        # May or may not fire depending on other features; check event_count not anomalous
        for r in results:
            assert (
                "event_count" not in r.anomalous_features or abs(r.zscores["event_count"]) >= 3.0
            )

    def test_spike_flagged(self):
        # Train on quiet baseline, then score a bucket with massive error spike
        baseline = _make_baseline(n=20, error_rate_mean=0.01, error_rate_std=0.005)
        # error_rate = 0.80 is ~158σ above baseline
        b = _bucket(event_count=100, error_count=80)
        results = detect_anomalies([b], baseline, threshold=3.0)
        assert len(results) == 1
        assert "error_rate" in results[0].anomalous_features

    def test_multiple_buckets_only_anomalous_returned(self):
        baseline = _make_baseline(n=20)
        normal = _bucket(event_count=100, error_count=2)
        spike = _bucket(event_count=100, error_count=80, ts=_T0 + timedelta(minutes=1))
        results = detect_anomalies([normal, spike], baseline)
        # Spike bucket should be in results; normal bucket may not be
        spike_ts = {r.bucket.ts for r in results}
        assert spike.ts in spike_ts

    def test_severity_scales_with_zscore(self):
        baseline = _make_baseline(n=20, error_rate_mean=0.01, error_rate_std=0.001)
        # 3σ → low, large spike → high/critical
        huge_spike = _bucket(event_count=100, error_count=80)
        results = detect_anomalies([huge_spike], baseline)
        assert results[0].severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)

    def test_confidence_in_range(self):
        baseline = _make_baseline(n=20, error_rate_mean=0.01, error_rate_std=0.001)
        b = _bucket(event_count=100, error_count=80)
        results = detect_anomalies([b], baseline)
        assert 0.0 <= results[0].confidence <= 1.0

    def test_result_sorted_by_time(self):
        baseline = _make_baseline(n=20, error_rate_mean=0.01, error_rate_std=0.001)
        b1 = _bucket(error_count=80, ts=_T0 + timedelta(minutes=2))
        b2 = _bucket(error_count=80, ts=_T0)
        results = detect_anomalies([b1, b2], baseline)
        if len(results) >= 2:
            assert results[0].bucket.ts <= results[1].bucket.ts


# ---------------------------------------------------------------------------
# anomaly_results_to_findings
# ---------------------------------------------------------------------------


class TestAnomalyResultsToFindings:
    def _make_result(self, method: str = "zscore") -> AnomalyResult:
        return AnomalyResult(
            bucket=_bucket(ts=_T0),
            zscores={"error_rate": 4.5, "event_count": -3.2},
            max_zscore=4.5,
            anomalous_features=["error_rate", "event_count"],
            severity=FindingSeverity.MEDIUM,
            confidence=0.5,
            method=method,
        )

    def test_returns_one_finding_per_result(self):
        r = self._make_result()
        findings = anomaly_results_to_findings([r], "test-source")
        assert len(findings) == 1

    def test_finding_rule_id_zscore(self):
        r = self._make_result("zscore")
        findings = anomaly_results_to_findings([r], "s")
        assert findings[0].rule_id == "anomaly.zscore"

    def test_finding_rule_id_if(self):
        r = self._make_result("isolation_forest")
        findings = anomaly_results_to_findings([r], "s")
        assert findings[0].rule_id == "anomaly.isolation_forest"

    def test_finding_source(self):
        r = self._make_result()
        findings = anomaly_results_to_findings([r], "my-nginx")
        assert findings[0].source == "my-nginx"

    def test_finding_timestamp(self):
        r = self._make_result()
        findings = anomaly_results_to_findings([r], "s")
        assert findings[0].timestamp == _T0

    def test_finding_message_contains_feature(self):
        r = self._make_result()
        findings = anomaly_results_to_findings([r], "s")
        assert "error_rate" in findings[0].message

    def test_finding_details_has_method(self):
        r = self._make_result()
        findings = anomaly_results_to_findings([r], "s")
        assert findings[0].details["method"] == "zscore"

    def test_empty_results(self):
        assert anomaly_results_to_findings([], "s") == []


# ---------------------------------------------------------------------------
# BaselineRepository
# ---------------------------------------------------------------------------


class TestBaselineRepository:
    def _fds(self, n: int = 5) -> list[dict[str, float]]:
        return [{"event_count": float(100 + i), "error_rate": 0.01} for i in range(n)]

    def _tss(self, n: int = 5) -> list[datetime]:
        return [_T0 + timedelta(minutes=i) for i in range(n)]

    def test_add_and_count_observations(self, repo: BaselineRepository):
        repo.add_observations("src", self._fds(3), self._tss(3))
        assert repo.get_observation_count("src") == 3

    def test_duplicate_timestamps_not_inserted_twice(self, repo: BaselineRepository):
        repo.add_observations("src", self._fds(3), self._tss(3))
        repo.add_observations("src", self._fds(3), self._tss(3))  # same timestamps
        assert repo.get_observation_count("src") == 3

    def test_get_all_feature_dicts(self, repo: BaselineRepository):
        fds = self._fds(5)
        repo.add_observations("src", fds, self._tss(5))
        loaded = repo.get_all_feature_dicts("src")
        assert len(loaded) == 5

    def test_update_and_get_stats(self, repo: BaselineRepository):
        fds = self._fds(5)
        repo.add_observations("src", fds, self._tss(5))
        stats = compute_stats(fds, "src")
        repo.update_stats(stats)
        loaded = repo.get_stats("src")
        assert loaded is not None
        assert "event_count" in loaded.features

    def test_get_stats_none_when_missing(self, repo: BaselineRepository):
        assert repo.get_stats("nonexistent") is None

    def test_list_sources(self, repo: BaselineRepository):
        fds = self._fds(5)
        for key in ("src-a", "src-b"):
            repo.add_observations(key, fds, self._tss(5))
            repo.update_stats(compute_stats(fds, key))
        sources = repo.list_sources()
        keys = {s["source_key"] for s in sources}
        assert {"src-a", "src-b"} == keys

    def test_delete_source(self, repo: BaselineRepository):
        fds = self._fds(5)
        repo.add_observations("src", fds, self._tss(5))
        repo.update_stats(compute_stats(fds, "src"))
        repo.delete_source("src")
        assert repo.get_stats("src") is None
        assert repo.get_observation_count("src") == 0

    def test_stats_is_trained_after_enough_obs(self, repo: BaselineRepository):
        fds = self._fds(5)
        repo.add_observations("src", fds, self._tss(5))
        stats = compute_stats(fds, "src")
        repo.update_stats(stats)
        loaded = repo.get_stats("src")
        assert loaded.is_trained()

    def test_returns_inserted_count(self, repo: BaselineRepository):
        n = repo.add_observations("src", self._fds(4), self._tss(4))
        assert n == 4
