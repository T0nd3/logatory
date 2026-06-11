"""Registry of source adapters, keyed by a stable name.

The name (``"file"``, ``"graylog"``, …) is the single source of truth for
*which adapters exist*. Fleet target validation, and later the plugin system,
read it instead of hardcoding their own lists — which used to drift out of
sync with the adapter set.

The registry maps a name to an :class:`AdapterSpec` (the adapter class plus a
little metadata). It deliberately does *not* know how to translate CLI flags
or fleet params into constructor arguments — that vocabulary lives with each
consumer (``fleet.factory`` for fleet targets, the per-source CLI commands
for the CLI). The registry only answers "what sources are there, and which
class implements each".
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import SourceAdapter
from .docker import DockerAdapter
from .file import FileAdapter
from .graylog import GraylogAdapter
from .journald import JournaldAdapter
from .kubernetes import KubernetesAdapter
from .loki import LokiAdapter
from .opensearch import OpenSearchAdapter
from .ssh import SSHAdapter
from .stdin import StdinAdapter
from .tail import TailAdapter
from .windows import WindowsEventLogAdapter


@dataclass(frozen=True)
class AdapterSpec:
    """A registered source adapter.

    ``fleet_target`` marks adapters that can be configured as a per-host fleet
    target. ``stdin`` and ``tail`` are excluded — they read the local process's
    stdin / a local file follow and aren't meaningful per remote host.
    """

    name: str
    adapter_cls: type[SourceAdapter]
    fleet_target: bool = True


_REGISTRY: dict[str, AdapterSpec] = {}


def register_adapter(spec: AdapterSpec) -> None:
    """Add or replace an adapter in the registry, keyed by ``spec.name``."""
    _REGISTRY[spec.name] = spec


def get_adapter_spec(name: str) -> AdapterSpec | None:
    """Return the spec registered under ``name``, or None if unknown."""
    return _REGISTRY.get(name)


def get_adapter_class(name: str) -> type[SourceAdapter] | None:
    """Return the adapter class registered under ``name``, or None."""
    spec = _REGISTRY.get(name)
    return spec.adapter_cls if spec is not None else None


def available_adapters() -> list[str]:
    """Return all registered adapter names, sorted."""
    return sorted(_REGISTRY)


def fleet_target_types() -> frozenset[str]:
    """Return the names of adapters usable as a fleet target."""
    return frozenset(name for name, spec in _REGISTRY.items() if spec.fleet_target)


# -- built-in adapters -----------------------------------------------------

for _spec in (
    AdapterSpec("file", FileAdapter),
    AdapterSpec("journald", JournaldAdapter),
    AdapterSpec("docker", DockerAdapter),
    AdapterSpec("kubernetes", KubernetesAdapter),
    AdapterSpec("windows", WindowsEventLogAdapter),
    AdapterSpec("ssh", SSHAdapter),
    AdapterSpec("loki", LokiAdapter),
    AdapterSpec("graylog", GraylogAdapter),
    AdapterSpec("opensearch", OpenSearchAdapter),
    AdapterSpec("stdin", StdinAdapter, fleet_target=False),
    AdapterSpec("tail", TailAdapter, fleet_target=False),
):
    register_adapter(_spec)

del _spec


__all__ = [
    "AdapterSpec",
    "SourceAdapter",
    "available_adapters",
    "fleet_target_types",
    "get_adapter_class",
    "get_adapter_spec",
    "register_adapter",
]
