from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class OpenSearchConfig:
    host: str = "localhost"
    port: int = 9200
    use_ssl: bool = False
    verify_certs: bool = True
    # Auth — loaded from env vars if not in config file
    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    ca_certs: str | None = None
    # Query defaults
    default_index: str = "logstash-*"
    timestamp_field: str = "@timestamp"
    message_field: str = "message"
    severity_field: str = "level"
    source_name_field: str = "host.name"

    @classmethod
    def from_dict(cls, data: dict) -> OpenSearchConfig:
        return cls(
            host=data.get("host", "localhost"),
            port=int(data.get("port", 9200)),
            use_ssl=bool(data.get("use_ssl", False)),
            verify_certs=bool(data.get("verify_certs", True)),
            username=os.environ.get("OPENSEARCH_USERNAME") or data.get("username"),
            password=os.environ.get("OPENSEARCH_PASSWORD") or data.get("password"),
            api_key=os.environ.get("OPENSEARCH_API_KEY") or data.get("api_key"),
            client_cert=os.environ.get("OPENSEARCH_CLIENT_CERT") or data.get("client_cert"),
            client_key=os.environ.get("OPENSEARCH_CLIENT_KEY") or data.get("client_key"),
            ca_certs=os.environ.get("OPENSEARCH_CA_CERTS") or data.get("ca_certs"),
            default_index=data.get("default_index", "logstash-*"),
            timestamp_field=data.get("timestamp_field", "@timestamp"),
            message_field=data.get("message_field", "message"),
            severity_field=data.get("severity_field", "level"),
            source_name_field=data.get("source_name_field", "host.name"),
        )


@dataclass
class AlertChannel:
    """A single alert destination configured under ``alerts:`` in config.yaml.

    ``type`` selects the notifier (``webhook`` | ``slack`` | ``discord`` |
    ``email``).  ``min_severity`` is the per-channel noise floor.  The remaining
    fields are type-specific: URL channels use ``url``; ``email`` uses the SMTP
    fields.  ``url`` and ``smtp_password`` are passed through ``expandvars`` so
    secrets can live in environment variables (e.g. ``url: ${SLACK_WEBHOOK}``).
    """

    type: str
    min_severity: str = "high"
    # Per-channel throttle: suppress repeats of the same finding (rule_id+source)
    # for this many seconds.  0 disables throttling (every match is delivered).
    cooldown: int = 0
    # webhook / slack / discord
    url: str | None = None
    # email (SMTP)
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    use_tls: bool = True
    sender: str | None = None
    recipients: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> AlertChannel:
        def expand(v):
            return os.path.expandvars(v) if isinstance(v, str) else v

        return cls(
            type=str(data.get("type", "")).strip().lower(),
            min_severity=str(data.get("min_severity", "high")).strip().lower(),
            cooldown=int(data.get("cooldown", 0)),
            url=expand(data.get("url")),
            smtp_host=data.get("smtp_host"),
            smtp_port=int(data.get("smtp_port", 587)),
            smtp_user=data.get("smtp_user"),
            smtp_password=expand(data.get("smtp_password")),
            use_tls=bool(data.get("use_tls", True)),
            sender=data.get("sender"),
            recipients=list(data.get("recipients", []) or []),
        )


@dataclass
class LLMConfig:
    provider: str = "ollama"
    model: str = "gemma3:4b"
    endpoint: str = "http://localhost:11434"
    temperature: float = 0.1
    max_context_tokens: int = 8000
    embed_model: str = "nomic-embed-text"
    # Cloud / API-key providers
    api_key: str | None = None  # loaded from env if not in config
    embed_provider: str | None = None  # if None, same as provider


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    opensearch: OpenSearchConfig = field(default_factory=OpenSearchConfig)
    pii_rules_path: Path = field(default_factory=lambda: Path("pii_rules.yaml"))
    db_path: Path = field(default_factory=lambda: Path("logatory.db"))
    pii_salt: str = ""
    # Finding persistence (Option B)
    findings_retention_days: int = 30  # auto-cleanup older than N days
    findings_min_severity: str = "high"  # "low" | "medium" | "high" | "critical"
    # REST API auth — None means auth disabled (local dev)
    api_token: str | None = None
    # Plugin directory — Python files here are auto-loaded at startup
    plugins_dir: Path | None = None
    # Alert channels — findings at/above each channel's min_severity are pushed
    alerts: list[AlertChannel] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        data: dict = {}
        if path and path.exists():
            with open(path) as f:
                data = yaml.safe_load(f) or {}

        llm_data = data.get("llm", {})
        llm = LLMConfig(
            provider=llm_data.get("provider", "ollama"),
            model=llm_data.get("model", "gemma3:4b"),
            endpoint=llm_data.get("endpoint", "http://localhost:11434"),
            temperature=float(llm_data.get("temperature", 0.1)),
            max_context_tokens=int(llm_data.get("max_context_tokens", 8000)),
            embed_model=llm_data.get("embed_model", "nomic-embed-text"),
            api_key=llm_data.get("api_key"),  # env-var fallback handled in factory
            embed_provider=llm_data.get("embed_provider"),
        )

        salt = os.environ.get("LOGATORY_PII_SALT") or data.get("pii_salt", "")

        api_token = os.environ.get("LOGATORY_API_TOKEN") or data.get("api_token") or None

        return cls(
            llm=llm,
            opensearch=OpenSearchConfig.from_dict(data.get("opensearch", {})),
            pii_rules_path=Path(data.get("pii_rules_path", "pii_rules.yaml")),
            db_path=Path(data.get("db_path", "logatory.db")),
            pii_salt=salt,
            findings_retention_days=int(data.get("findings_retention_days", 30)),
            findings_min_severity=data.get("findings_min_severity", "high"),
            api_token=api_token,
            plugins_dir=Path(data["plugins_dir"]) if data.get("plugins_dir") else None,
            alerts=[AlertChannel.from_dict(c) for c in (data.get("alerts") or [])],
        )
