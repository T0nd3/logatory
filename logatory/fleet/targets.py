"""Fleet target configuration — loads a targets file into Target objects.

A targets file lists named log sources to pull from as a fleet. Each target
has a `type` (matching a source adapter) plus that adapter's parameters, and
optional `groups` for selecting subsets. Secrets stay out of the file via
`${ENV_VAR}` interpolation.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..adapters import fleet_target_types

# Target types that map to a source adapter, taken straight from the adapter
# registry (stdin and tail are excluded there — they aren't per-host sources).
TARGET_TYPES = fleet_target_types()

_ENV_RE = re.compile(r"\$\{(\w+)\}")


class TargetConfigError(Exception):
    """Raised when a targets file is missing, malformed, or invalid."""


@dataclass
class Target:
    """One configured log source in a fleet."""

    name: str
    type: str
    params: dict
    groups: list[str] = field(default_factory=list)


def _interpolate(value):
    """Recursively replace `${ENV_VAR}` in strings with environment values."""
    if isinstance(value, str):

        def _sub(m):
            var = m.group(1)
            env = os.environ.get(var)
            if env is None:
                raise TargetConfigError(f"environment variable '{var}' is not set")
            return env

        return _ENV_RE.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


def load_targets(path: Path) -> list[Target]:
    """Load and validate a targets file into a list of Target objects."""
    if not path.exists():
        raise TargetConfigError(f"targets file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise TargetConfigError(f"invalid YAML in {path}: {e}")
    if not isinstance(data, dict):
        raise TargetConfigError(f"{path} must be a mapping with a 'targets:' list")

    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list) or not raw_targets:
        raise TargetConfigError(f"{path} has no 'targets:' list")

    targets: list[Target] = []
    seen: set[str] = set()
    for i, entry in enumerate(raw_targets):
        if not isinstance(entry, dict):
            raise TargetConfigError(f"target #{i + 1} is not a mapping")

        name = entry.get("name")
        if not name or not isinstance(name, str):
            raise TargetConfigError(f"target #{i + 1} is missing a 'name'")
        if name in seen:
            raise TargetConfigError(f"duplicate target name: '{name}'")
        seen.add(name)

        ttype = entry.get("type")
        if ttype not in TARGET_TYPES:
            raise TargetConfigError(
                f"target '{name}' has invalid type '{ttype}' "
                f"(expected one of: {', '.join(sorted(TARGET_TYPES))})"
            )

        groups = entry.get("groups", [])
        if isinstance(groups, str):
            groups = [groups]
        elif not isinstance(groups, list):
            raise TargetConfigError(f"target '{name}': 'groups' must be a list")

        params = {
            k: _interpolate(v) for k, v in entry.items() if k not in ("name", "type", "groups")
        }
        targets.append(
            Target(name=name, type=ttype, params=params, groups=[str(g) for g in groups])
        )

    return targets


def select_targets(
    targets: list[Target],
    names: list[str] | None = None,
    groups: list[str] | None = None,
) -> list[Target]:
    """Filter targets by explicit names and/or group membership.

    With no filter, every target is returned. Raises TargetConfigError if a
    requested name or group matches nothing.
    """
    if not names and not groups:
        return list(targets)

    all_names = {t.name for t in targets}
    all_groups = {g for t in targets for g in t.groups}
    for n in names or []:
        if n not in all_names:
            raise TargetConfigError(f"no target named '{n}'")
    for g in groups or []:
        if g not in all_groups:
            raise TargetConfigError(f"no target in group '{g}'")

    name_set = set(names or [])
    group_set = set(groups or [])
    return [t for t in targets if t.name in name_set or (group_set & set(t.groups))]
