"""Tests for the Kubernetes source adapter."""

from __future__ import annotations

import json

from logatory.adapters.kubernetes import KubernetesAdapter, _parse_ts, _rfc3339
from logatory.models import Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pod(name: str, namespace: str = "default", containers: list[str] | None = None) -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"containers": [{"name": c} for c in (containers or ["app"])]},
    }


def _pod_list(*pods: dict) -> str:
    return json.dumps({"kind": "List", "items": list(pods)})


def _logs(*lines: str) -> str:
    return "\n".join(lines)


def _ts_line(ts: str, content: str) -> str:
    return f"{ts} {content}"


class _Runner:
    """Injectable kubectl stand-in.

    ``get pods`` calls return ``pods_output``; ``logs`` calls return the next
    queued logs response. Records every argv for assertions.
    """

    def __init__(self, pods_output: str, *logs_responses: str) -> None:
        self._pods_output = pods_output
        self._logs = list(logs_responses)
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        if "get" in args:
            return self._pods_output
        if "logs" in args:
            return self._logs.pop(0) if self._logs else ""
        return ""

    @property
    def log_calls(self) -> list[list[str]]:
        return [c for c in self.calls if "logs" in c]


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------


class TestTimestamps:
    def test_parse_rfc3339_nano(self):
        dt = _parse_ts("2026-05-18T10:00:00.123456789Z")
        assert dt is not None
        assert dt.year == 2026 and dt.microsecond == 123456

    def test_parse_invalid_returns_none(self):
        assert _parse_ts("not-a-timestamp") is None

    def test_rfc3339_roundtrips_into_parse(self):
        dt = _parse_ts("2026-05-18T10:00:00.500000Z")
        assert dt is not None
        # The rendered form must be re-parseable (kubectl --since-time input).
        assert _parse_ts(_rfc3339(dt)) is not None


# ---------------------------------------------------------------------------
# Pod discovery
# ---------------------------------------------------------------------------


class TestListPods:
    def test_lists_pods_with_containers(self):
        runner = _Runner(_pod_list(_pod("api-1", containers=["app", "sidecar"])))
        adapter = KubernetesAdapter(runner=runner)
        pods = adapter._list_pods()
        assert pods == [("default", "api-1", ["app", "sidecar"])]

    def test_single_pod_object_is_handled(self):
        single = json.dumps({"kind": "Pod", **_pod("solo", namespace="prod")})
        runner = _Runner(single)
        adapter = KubernetesAdapter(pod="solo", namespace="prod", runner=runner)
        pods = adapter._list_pods()
        assert pods == [("prod", "solo", ["app"])]

    def test_selector_and_namespace_forwarded(self):
        runner = _Runner(_pod_list(_pod("api-1")))
        adapter = KubernetesAdapter(namespace="prod", selector="app=api", runner=runner)
        adapter._list_pods()
        args = runner.calls[0]
        assert "-n" in args and "prod" in args
        assert "-l" in args and "app=api" in args

    def test_all_namespaces_flag(self):
        runner = _Runner(_pod_list(_pod("api-1")))
        adapter = KubernetesAdapter(all_namespaces=True, runner=runner)
        adapter._list_pods()
        assert "--all-namespaces" in runner.calls[0]

    def test_empty_output_returns_no_pods(self):
        runner = _Runner("")
        adapter = KubernetesAdapter(runner=runner)
        assert adapter._list_pods() == []


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_yields_events_tagged_with_pod(self):
        runner = _Runner(
            _pod_list(_pod("api-1", containers=["app"])),
            _logs(
                _ts_line("2026-05-18T10:00:00.000000Z", "hello world"),
                _ts_line("2026-05-18T10:00:01.000000Z", "second line"),
            ),
        )
        adapter = KubernetesAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["hello world", "second line"]
        assert events[0].source == "default/api-1/app"
        assert events[0].parsed_fields["namespace"] == "default"
        assert events[0].parsed_fields["pod"] == "api-1"
        assert events[0].parsed_fields["container"] == "app"

    async def test_kubectl_timestamp_used_when_parser_finds_none(self):
        runner = _Runner(
            _pod_list(_pod("api-1")),
            _logs(_ts_line("2026-05-18T10:00:00.000000Z", "plain text line")),
        )
        adapter = KubernetesAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].timestamp is not None
        assert events[0].timestamp.year == 2026

    async def test_inner_json_is_parsed(self):
        runner = _Runner(
            _pod_list(_pod("api-1")),
            _logs(
                _ts_line(
                    "2026-05-18T10:00:00.000000Z",
                    '{"level": "error", "message": "DB down"}',
                )
            ),
        )
        adapter = KubernetesAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert events[0].severity == Severity.ERROR
        assert events[0].message == "DB down"

    async def test_multiple_containers_each_read(self):
        runner = _Runner(
            _pod_list(_pod("api-1", containers=["app", "sidecar"])),
            _logs(_ts_line("2026-05-18T10:00:00.000000Z", "from app")),
            _logs(_ts_line("2026-05-18T10:00:00.000000Z", "from sidecar")),
        )
        adapter = KubernetesAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert {e.message for e in events} == {"from app", "from sidecar"}
        assert len(runner.log_calls) == 2

    async def test_container_filter_limits_reads(self):
        runner = _Runner(
            _pod_list(_pod("api-1", containers=["app", "sidecar"])),
            _logs(_ts_line("2026-05-18T10:00:00.000000Z", "from app")),
        )
        adapter = KubernetesAdapter(container="app", runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["from app"]
        assert len(runner.log_calls) == 1
        assert "-c" in runner.log_calls[0] and "app" in runner.log_calls[0]

    async def test_since_forwarded_to_logs(self):
        runner = _Runner(
            _pod_list(_pod("api-1")),
            _logs(_ts_line("2026-05-18T10:00:00.000000Z", "x")),
        )
        adapter = KubernetesAdapter(since="5m", runner=runner)
        _ = [e async for e in adapter.events()]
        assert "--since" in runner.log_calls[0]
        assert "5m" in runner.log_calls[0]

    async def test_blank_lines_skipped(self):
        runner = _Runner(
            _pod_list(_pod("api-1")),
            _logs(_ts_line("2026-05-18T10:00:00.000000Z", "kept"), "", "   "),
        )
        adapter = KubernetesAdapter(runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["kept"]


# ---------------------------------------------------------------------------
# Realtime polling
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_poll_skips_already_seen_and_advances_cursor(self):
        runner = _Runner(
            _pod_list(_pod("api-1")),
            # round 1
            _logs(
                _ts_line("2026-05-18T10:00:00.000000Z", "first"),
                _ts_line("2026-05-18T10:00:01.000000Z", "second"),
            ),
            # round 2: re-delivers 'second' (since-time is inclusive) plus a new line
            _logs(
                _ts_line("2026-05-18T10:00:01.000000Z", "second"),
                _ts_line("2026-05-18T10:00:02.000000Z", "third"),
            ),
        )
        adapter = KubernetesAdapter(runner=runner)

        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 3:
                break

        assert collected == ["first", "second", "third"]
        # The second logs call must carry a --since-time cursor.
        assert "--since-time" in runner.log_calls[1]
