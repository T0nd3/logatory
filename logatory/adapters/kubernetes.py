"""Kubernetes source adapter — reads pod logs via the `kubectl` CLI.

For clusters without a central log stack (or when you just want an ad-hoc
look), this adapter pulls container logs straight through `kubectl logs`.
It shells out to the system `kubectl` (no Python Kubernetes dependency), so
your current kube-context, `~/.kube/config`, auth plugins and RBAC all apply
unchanged. Read-only — it only ever runs `get pods` and `logs`.

Pods are discovered with `kubectl get pods -o json` (honouring a namespace
and/or label selector); each container's logs are then fetched with
`--timestamps`, and the inner content is parsed exactly like any other
source (JSON, logfmt, plaintext, …). Every event is tagged with its
namespace, pod and container.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter

# RFC3339(Nano) timestamp prefix that `kubectl logs --timestamps` puts on each
# line, followed by a single space and the actual log content.
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s")


def _parse_ts(token: str) -> datetime | None:
    """Parse an RFC3339(Nano) timestamp; over-long fractions are truncated."""
    token = token.replace("Z", "+00:00")
    token = re.sub(r"(\.\d{6})\d+", r"\1", token)  # microseconds is datetime's limit
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class KubernetesAdapter(SourceAdapter):
    """Reads log events from Kubernetes pods via the system `kubectl` client.

    Targets are selected by namespace and/or label selector, or a single pod
    by name. Each matching pod's containers are read individually so events
    can be tagged with the exact container they came from.
    """

    def __init__(
        self,
        *,
        namespace: str | None = None,
        selector: str | None = None,
        pod: str | None = None,
        container: str | None = None,
        all_namespaces: bool = False,
        tail: int = 200,
        since: str | None = None,
        context: str | None = None,
        kubeconfig: str | None = None,
        runner=None,
    ) -> None:
        self._namespace = namespace
        self._selector = selector
        self._pod = pod
        self._container = container
        self._all_namespaces = all_namespaces
        self._tail = tail
        self._since = since
        self._context = context
        self._kubeconfig = kubeconfig
        self._runner = runner  # injectable for tests: (list[str]) -> str

    # -- kubectl command construction --------------------------------------

    def _base(self) -> list[str]:
        args = ["kubectl"]
        if self._kubeconfig:
            args += ["--kubeconfig", self._kubeconfig]
        if self._context:
            args += ["--context", self._context]
        return args

    def _namespace_args(self) -> list[str]:
        if self._all_namespaces:
            return ["--all-namespaces"]
        if self._namespace:
            return ["-n", self._namespace]
        return []

    def _list_args(self) -> list[str]:
        args = [*self._base(), "get", "pods", "-o", "json", *self._namespace_args()]
        if self._selector:
            args += ["-l", self._selector]
        if self._pod:
            args.append(self._pod)
        return args

    def _logs_args(
        self, namespace: str, pod: str, container: str | None, since_time: str | None
    ) -> list[str]:
        args = [*self._base(), "logs", pod, "--timestamps", "--tail", str(self._tail)]
        if namespace:
            args += ["-n", namespace]
        if container:
            args += ["-c", container]
        if since_time:
            args += ["--since-time", since_time]
        elif self._since:
            args += ["--since", self._since]
        return args

    # -- runner (real subprocess; overridable for tests) -------------------

    def _run(self, args: list[str]) -> str:
        if self._runner is not None:
            return self._runner(args)
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError(
                "kubectl not found — install the Kubernetes CLI to use the kubernetes adapter."
            )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"kubectl failed: {detail}")
        return result.stdout

    # -- pod / log parsing -------------------------------------------------

    def _list_pods(self) -> list[tuple[str, str, list[str]]]:
        """Return (namespace, pod, container_names) for every matching pod."""
        output = self._run(self._list_args())
        try:
            data = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []

        items = data.get("items") if isinstance(data, dict) else None
        if items is None:
            # A single-pod `get pods <name> -o json` returns the Pod directly.
            items = [data] if isinstance(data, dict) and data.get("kind") == "Pod" else []

        pods: list[tuple[str, str, list[str]]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            meta = item.get("metadata") or {}
            name = meta.get("name")
            if not name:
                continue
            ns = meta.get("namespace") or self._namespace or "default"
            spec = item.get("spec") or {}
            containers = [
                c["name"]
                for c in spec.get("containers", [])
                if isinstance(c, dict) and "name" in c
            ]
            pods.append((ns, name, containers))
        return pods

    def _read_lines(
        self, namespace: str, pod: str, container: str | None, *, since_time: str | None
    ) -> list[tuple[datetime | None, str]]:
        """Fetch one container's logs as (timestamp, content) pairs."""
        output = self._run(self._logs_args(namespace, pod, container, since_time))
        pairs: list[tuple[datetime | None, str]] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            m = _TS_RE.match(line)
            if m:
                pairs.append((_parse_ts(m.group(1)), line[m.end() :]))
            else:
                pairs.append((None, line))
        return pairs

    def _targets(self) -> list[tuple[str, str, str | None]]:
        """Flatten matching pods into (namespace, pod, container) read targets."""
        targets: list[tuple[str, str, str | None]] = []
        for ns, pod, containers in self._list_pods():
            if self._container:
                targets.append((ns, pod, self._container))
            elif containers:
                targets.extend((ns, pod, c) for c in containers)
            else:
                targets.append((ns, pod, None))
        return targets

    @staticmethod
    def _source_name(namespace: str, pod: str, container: str | None) -> str:
        name = f"{namespace}/{pod}"
        return f"{name}/{container}" if container else name

    @staticmethod
    def _to_event(
        parser,
        ts: datetime | None,
        content: str,
        namespace: str,
        pod: str,
        container: str | None,
    ) -> Event | None:
        event = parser.parse(content)
        if event is None:
            return None
        event.source = KubernetesAdapter._source_name(namespace, pod, container)
        # kubectl's own timestamp is reliable; use it if the parser found none.
        if event.timestamp is None and ts is not None:
            event.timestamp = ts
        event.parsed_fields["namespace"] = namespace
        event.parsed_fields["pod"] = pod
        if container:
            event.parsed_fields["container"] = container
        return event

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield every event from matching pods once (batch mode)."""
        for ns, pod, container in self._targets():
            pairs = self._read_lines(ns, pod, container, since_time=None)
            if not pairs:
                continue
            name = self._source_name(ns, pod, container)
            sample = [content for _, content in pairs[:5] if content.strip()]
            parser = get_parser(FormatDetector().detect(sample), source=name)
            for ts, content in pairs:
                event = self._to_event(parser, ts, content, ns, pod, container)
                if event is not None:
                    yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll matching pods forever, yielding only newly-arrived events.

        Pods are re-listed every round, so pods scheduled after the poll began
        are picked up automatically. New lines are tracked per container via a
        timestamp cursor passed back as ``--since-time`` — kubectl's
        nanosecond timestamps make a same-instant collision very unlikely.
        Runs until the caller stops iterating.
        """
        cursors: dict[tuple[str, str, str | None], datetime] = {}
        parsers: dict[tuple[str, str, str | None], object] = {}

        while True:
            for ns, pod, container in self._targets():
                key = (ns, pod, container)
                cursor = cursors.get(key)
                since_time = _rfc3339(cursor) if cursor else None
                pairs = self._read_lines(ns, pod, container, since_time=since_time)
                if not pairs:
                    continue
                if key not in parsers:
                    name = self._source_name(ns, pod, container)
                    sample = [c for _, c in pairs[:5] if c.strip()]
                    parsers[key] = get_parser(FormatDetector().detect(sample), source=name)
                parser = parsers[key]
                newest = cursor
                for ts, content in pairs:
                    if ts is not None and cursor is not None and ts <= cursor:
                        continue  # already delivered in an earlier round
                    event = self._to_event(parser, ts, content, ns, pod, container)
                    if event is not None:
                        yield event
                    if ts is not None and (newest is None or ts > newest):
                        newest = ts
                if newest is not None:
                    cursors[key] = newest

            await asyncio.sleep(interval)


def _rfc3339(dt: datetime) -> str:
    """Render a datetime as the RFC3339 string kubectl's --since-time wants."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
