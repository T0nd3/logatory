"""Anomaly detection: z-score (always available) + optional Isolation Forest.

Usage
-----
    results = detect_anomalies(buckets, baseline, threshold=3.0)
    findings = anomaly_results_to_findings(results, source="nginx")

Isolation Forest is used automatically when scikit-learn is installed and the
baseline has enough observations (>= 20 buckets).  Results from both methods
are merged — whichever flags a bucket first wins.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass

from ..models import Finding, FindingSeverity
from .baseline import BaselineStats
from .features import TimeBucket

_IF_MIN_BUCKETS = 20  # Isolation Forest needs more data than z-score


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def _severity_for_zscore(z: float) -> FindingSeverity:
    az = abs(z)
    if az >= 7.0:
        return FindingSeverity.CRITICAL
    if az >= 5.0:
        return FindingSeverity.HIGH
    if az >= 4.0:
        return FindingSeverity.MEDIUM
    return FindingSeverity.LOW


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class AnomalyResult:
    bucket: TimeBucket
    zscores: dict[str, float]
    max_zscore: float
    anomalous_features: list[str]
    severity: FindingSeverity
    confidence: float  # 0.0–1.0
    method: str = "zscore"  # "zscore" | "isolation_forest"


# ---------------------------------------------------------------------------
# Z-score detection
# ---------------------------------------------------------------------------


def _zscore_detect(
    buckets: list[TimeBucket],
    baseline: BaselineStats,
    threshold: float,
) -> list[AnomalyResult]:
    results: list[AnomalyResult] = []
    for bucket in buckets:
        fd = bucket.to_feature_dict()
        zs = baseline.zscore_dict(fd)
        anomalous = [name for name, z in zs.items() if abs(z) >= threshold]
        if not anomalous:
            continue
        max_z = max(abs(zs[name]) for name in anomalous)
        # Confidence scales linearly from threshold to 2*threshold → 0..1
        confidence = min(1.0, (max_z - threshold) / max(threshold, 1e-10))
        results.append(
            AnomalyResult(
                bucket=bucket,
                zscores=zs,
                max_zscore=max_z,
                anomalous_features=anomalous,
                severity=_severity_for_zscore(max_z),
                confidence=round(confidence, 3),
                method="zscore",
            )
        )
    return results


# ---------------------------------------------------------------------------
# Isolation Forest (optional)
# ---------------------------------------------------------------------------


def _if_available() -> bool:
    return importlib.util.find_spec("sklearn") is not None


def _if_detect(
    buckets: list[TimeBucket],
    baseline_feature_dicts: list[dict[str, float]],
    threshold: float,
) -> list[AnomalyResult]:
    """Train Isolation Forest on baseline observations, score current buckets."""
    import numpy as np  # type: ignore[import]
    from sklearn.ensemble import IsolationForest  # type: ignore[import]

    if not baseline_feature_dicts or not buckets:
        return []

    feature_names = sorted(baseline_feature_dicts[0].keys())

    def _to_matrix(dicts: list[dict[str, float]]) -> np.ndarray:
        return np.array([[d.get(f, 0.0) for f in feature_names] for d in dicts])

    X_train = _to_matrix(baseline_feature_dicts)
    X_test = _to_matrix([b.to_feature_dict() for b in buckets])

    # contamination: fraction of outliers expected in training data
    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X_train)

    # decision_function: negative = more anomalous (range roughly -0.5 to 0.5)
    scores = clf.decision_function(X_test)
    predictions = clf.predict(X_test)  # -1 = anomaly, 1 = normal

    results: list[AnomalyResult] = []
    for _i, (bucket, score, pred) in enumerate(zip(buckets, scores, predictions)):
        if pred != -1:
            continue
        # Map score to [0,1] confidence: score ≈ -0.5 = very anomalous
        confidence = min(1.0, max(0.0, (-score) * 2))
        # Approximate severity from confidence
        if confidence >= 0.8:
            sev = FindingSeverity.CRITICAL
        elif confidence >= 0.6:
            sev = FindingSeverity.HIGH
        elif confidence >= 0.4:
            sev = FindingSeverity.MEDIUM
        else:
            sev = FindingSeverity.LOW
        results.append(
            AnomalyResult(
                bucket=bucket,
                zscores={},  # IF doesn't give per-feature z-scores
                max_zscore=abs(score) * 10,  # pseudo-z for display
                anomalous_features=feature_names,
                severity=sev,
                confidence=round(confidence, 3),
                method="isolation_forest",
            )
        )
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_anomalies(
    buckets: list[TimeBucket],
    baseline: BaselineStats,
    threshold: float = 3.0,
    baseline_feature_dicts: list[dict[str, float]] | None = None,
) -> list[AnomalyResult]:
    """Score buckets against the baseline and return anomalous ones.

    Always runs z-score detection.  If scikit-learn is available and enough
    training data exists, also runs Isolation Forest and merges results.
    Deduplicates by bucket timestamp.
    """
    if not baseline.is_trained():
        return []

    zscore_results = _zscore_detect(buckets, baseline, threshold)

    # Optionally add Isolation Forest results
    if_results: list[AnomalyResult] = []
    if (
        _if_available()
        and baseline_feature_dicts is not None
        and len(baseline_feature_dicts) >= _IF_MIN_BUCKETS
    ):
        if_results = _if_detect(buckets, baseline_feature_dicts, threshold)

    # Merge: prefer z-score result if same bucket is flagged by both
    seen_ts = {r.bucket.ts for r in zscore_results}
    merged = list(zscore_results)
    for r in if_results:
        if r.bucket.ts not in seen_ts:
            merged.append(r)
            seen_ts.add(r.bucket.ts)

    return sorted(merged, key=lambda r: r.bucket.ts)


def anomaly_results_to_findings(
    results: list[AnomalyResult],
    source: str,
) -> list[Finding]:
    """Convert AnomalyResult list into Finding objects compatible with the rule engine output."""
    findings: list[Finding] = []
    for r in results:
        if r.method == "zscore":
            # Pick the most extreme feature for the headline
            top_feat = max(r.anomalous_features, key=lambda f: abs(r.zscores.get(f, 0)))
            top_z = r.zscores.get(top_feat, 0.0)
            direction = "above" if top_z > 0 else "below"
            message = (
                f"Anomaly at {r.bucket.ts.strftime('%H:%M:%S')}: "
                f"{top_feat} is {abs(top_z):.1f}σ {direction} baseline"
            )
            others = [f for f in r.anomalous_features if f != top_feat]
            if others:
                other_str = ", ".join(f"{f} ({r.zscores.get(f, 0):+.1f}σ)" for f in others[:3])
                message += f"  [{other_str}]"
        else:
            message = (
                f"Isolation Forest anomaly at {r.bucket.ts.strftime('%H:%M:%S')} "
                f"(confidence {r.confidence:.0%})"
            )

        findings.append(
            Finding(
                rule_id=f"anomaly.{r.method}",
                severity=r.severity,
                message=message,
                source=source,
                timestamp=r.bucket.ts,
                events=[],
                details={
                    "bucket_ts": r.bucket.ts.isoformat(),
                    "method": r.method,
                    "max_zscore": round(r.max_zscore, 2),
                    "confidence": r.confidence,
                    "anomalous_features": r.anomalous_features,
                    "zscores": {k: round(v, 2) for k, v in r.zscores.items()},
                    "features": r.bucket.to_feature_dict(),
                },
            )
        )
    return findings
