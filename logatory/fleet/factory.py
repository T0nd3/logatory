"""Adapter factory — turns a fleet Target into a concrete SourceAdapter.

SSH is just a transport and the HTTP adapters need no extra dependency, but
`docker` and `opensearch` targets require their optional packages at run
time. The adapter modules import lazily, so building a Target only fails if
that target's adapter is actually used without its dependency.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..adapters.base import SourceAdapter
from ..adapters.cloudwatch import CloudWatchAdapter
from ..adapters.docker import DockerAdapter
from ..adapters.file import FileAdapter
from ..adapters.gcp_logging import GCPLoggingAdapter
from ..adapters.graylog import GraylogAdapter
from ..adapters.journald import JournaldAdapter
from ..adapters.kubernetes import KubernetesAdapter
from ..adapters.loki import LokiAdapter
from ..adapters.opensearch import OpenSearchAdapter
from ..adapters.opensearch_config import (
    FieldMapping,
    OpenSearchAuth,
    OpenSearchQuery,
    TimeRange,
)
from ..adapters.s3 import S3Adapter
from ..adapters.ssh import SSHAdapter
from ..adapters.windows import WindowsEventLogAdapter
from .targets import Target, TargetConfigError


def _opt_int(params: dict, key: str) -> int | None:
    """Read an optional integer param, coercing env-interpolated strings."""
    value = params.get(key)
    return int(value) if value is not None else None


def _require(target: Target, key: str):
    value = target.params.get(key)
    if not value:
        raise TargetConfigError(f"target '{target.name}': type '{target.type}' needs a '{key}'")
    return value


# Per-type builders translate a target's params into a constructed adapter.
# Keyed by the same names the adapter registry uses for fleet targets; the
# `_build_dispatch_matches_registry` test keeps the two sets in lockstep.


def _build_file(target: Target) -> SourceAdapter:
    return FileAdapter(Path(_require(target, "path")))


def _build_journald(target: Target) -> SourceAdapter:
    p = target.params
    return JournaldAdapter(
        unit=p.get("unit"),
        since=p.get("since"),
        lines=_opt_int(p, "lines"),
    )


def _build_docker(target: Target) -> SourceAdapter:
    p = target.params
    return DockerAdapter(
        name=p.get("name"),
        label=p.get("label"),
        include_stopped=bool(p.get("include_stopped", False)),
        tail=_opt_int(p, "tail") or 200,
    )


def _build_kubernetes(target: Target) -> SourceAdapter:
    p = target.params
    return KubernetesAdapter(
        namespace=p.get("namespace"),
        selector=p.get("selector"),
        pod=p.get("pod"),
        container=p.get("container"),
        all_namespaces=bool(p.get("all_namespaces", False)),
        tail=_opt_int(p, "tail") or 200,
        since=p.get("since"),
        context=p.get("context"),
        kubeconfig=p.get("kubeconfig"),
    )


def _build_windows(target: Target) -> SourceAdapter:
    p = target.params
    return WindowsEventLogAdapter(
        path=p.get("path"),
        log=p.get("log"),
        max_events=_opt_int(p, "max_events") or 200,
        provider=p.get("provider"),
    )


def _build_s3(target: Target) -> SourceAdapter:
    p = target.params
    return S3Adapter(
        bucket=_require(target, "bucket"),
        prefix=p.get("prefix"),
        endpoint_url=p.get("endpoint_url"),
        region=p.get("region"),
        profile=p.get("profile"),
        max_objects=_opt_int(p, "max_objects") or 50,
    )


def _build_cloudwatch(target: Target) -> SourceAdapter:
    p = target.params
    return CloudWatchAdapter(
        log_group=_require(target, "log_group"),
        log_stream=p.get("log_stream"),
        filter_pattern=p.get("filter_pattern"),
        since=p.get("since"),
        region=p.get("region"),
        profile=p.get("profile"),
        limit=_opt_int(p, "limit") or 1000,
    )


def _build_gcp(target: Target) -> SourceAdapter:
    p = target.params
    return GCPLoggingAdapter(
        log_filter=p.get("filter"),
        project=p.get("project"),
        since=p.get("since", "1h"),
        limit=_opt_int(p, "limit") or 1000,
    )


def _build_ssh(target: Target) -> SourceAdapter:
    p = target.params
    return SSHAdapter(
        host=_require(target, "host"),
        path=p.get("path"),
        unit=p.get("unit"),
        use_journald=bool(p.get("journald", False)),
        since=p.get("since"),
        lines=_opt_int(p, "lines") or 1000,
        port=_opt_int(p, "port"),
        identity=p.get("identity"),
        ssh_opts=p.get("ssh_opts"),
    )


def _build_loki(target: Target) -> SourceAdapter:
    p = target.params
    return LokiAdapter(
        url=p.get("url", "http://localhost:3100"),
        query=p.get("query", '{job=~".+"}'),
        limit=_opt_int(p, "limit") or 1000,
        source_label=p.get("source_label", "job"),
        username=p.get("username"),
        password=p.get("password"),
        token=p.get("token"),
        org_id=p.get("org_id"),
    )


def _build_graylog(target: Target) -> SourceAdapter:
    p = target.params
    return GraylogAdapter(
        url=p.get("url", "http://localhost:9000"),
        query=p.get("query", "*"),
        range_seconds=_opt_int(p, "range_seconds") or 3600,
        limit=_opt_int(p, "limit") or 1000,
        username=p.get("username"),
        password=p.get("password"),
        token=p.get("token"),
    )


def _build_opensearch(target: Target) -> SourceAdapter:
    p = target.params
    auth = OpenSearchAuth(
        username=p.get("username"),
        password=p.get("password"),
        api_key=p.get("api_key"),
    )
    query = OpenSearchQuery(
        index=p.get("index", "logstash-*"),
        time_range=TimeRange(since=p.get("since"), until=p.get("until")),
        field_mapping=FieldMapping(
            timestamp=p.get("ts_field", "@timestamp"),
            message=p.get("msg_field", "message"),
            severity=p.get("sev_field", "level"),
            source_name=p.get("src_field", "host.name"),
        ),
    )
    return OpenSearchAdapter(
        host=p.get("host", "localhost"),
        port=_opt_int(p, "port") or 9200,
        query=query,
        auth=auth if (auth.username or auth.api_key) else None,
        use_ssl=bool(p.get("use_ssl", False)),
        verify_certs=not bool(p.get("no_verify_certs", False)),
    )


_BUILDERS: dict[str, Callable[[Target], SourceAdapter]] = {
    "file": _build_file,
    "journald": _build_journald,
    "docker": _build_docker,
    "kubernetes": _build_kubernetes,
    "windows": _build_windows,
    "s3": _build_s3,
    "cloudwatch": _build_cloudwatch,
    "gcp": _build_gcp,
    "ssh": _build_ssh,
    "loki": _build_loki,
    "graylog": _build_graylog,
    "opensearch": _build_opensearch,
}


def build_adapter(target: Target) -> SourceAdapter:
    """Construct the source adapter described by a Target."""
    builder = _BUILDERS.get(target.type)
    if builder is None:
        # load_targets validates the type, so this is unreachable in practice
        raise TargetConfigError(f"target '{target.name}': unknown type '{target.type}'")
    return builder(target)
