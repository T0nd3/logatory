"""Field schema per target type.

Single source of truth for the configurable fields of each target type — it
drives both the `fleet init` CLI wizard and the browser config editor, so
the two front-ends stay consistent with the adapters.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Field:
    """One configurable field of a fleet target type.

    kind: "str" — a plain text value
          "bool" — a yes/no flag (written as a real YAML boolean)
          "secret" — a credential; the wizard asks for an env-var name and
                     writes ``${VAR}`` rather than the value itself
    """

    name: str
    label: str
    required: bool = False
    default: str = ""
    kind: str = "str"


# Common fields per type. Exotic adapter options can still be hand-added to
# the generated targets.yaml — this covers the everyday case.
TYPE_FIELDS: dict[str, list[Field]] = {
    "file": [
        Field("path", "Log file path", required=True),
    ],
    "journald": [
        Field("unit", "systemd unit, e.g. nginx.service (optional)"),
        Field("since", "Lookback window, e.g. -1h (optional)"),
    ],
    "docker": [
        Field("name", "Container name filter (optional)"),
        Field("label", "Container label filter, key=value (optional)"),
        Field("include_stopped", "Include stopped containers?", kind="bool"),
    ],
    "kubernetes": [
        Field("namespace", "Namespace (optional)"),
        Field("selector", "Label selector, e.g. app=api (optional)"),
        Field("pod", "Single pod name (optional)"),
        Field("container", "Container name (optional)"),
        Field("context", "kubeconfig context (optional)"),
    ],
    "ssh": [
        Field("host", "SSH host — user@host or an ssh-config alias", required=True),
        Field("journald", "Read the remote systemd journal (instead of a file)?", kind="bool"),
        Field("unit", "journald unit, if journald (optional)"),
        Field("path", "Remote log file path, if not journald"),
        Field("port", "SSH port (optional)"),
        Field("identity", "SSH private key file (optional)"),
    ],
    "loki": [
        Field("url", "Loki base URL", default="http://localhost:3100"),
        Field("query", "LogQL stream selector", default='{job=~".+"}'),
        Field("token", "Bearer token", kind="secret"),
        Field("org_id", "X-Scope-OrgID tenant (optional)"),
    ],
    "graylog": [
        Field("url", "Graylog base URL", default="http://localhost:9000"),
        Field("query", "Graylog search query", default="*"),
        Field("token", "Graylog access token", kind="secret"),
    ],
    "opensearch": [
        Field("host", "OpenSearch host", default="localhost"),
        Field("port", "OpenSearch port", default="9200"),
        Field("index", "Index pattern", default="logstash-*"),
        Field("username", "Username (optional)"),
        Field("password", "Password", kind="secret"),
    ],
}
