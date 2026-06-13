# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Parser:** Traefik access log in its *common* format (the extended common log
  with Traefik's trailing request-count / router / server / duration fields).
  Auto-detected ahead of nginx so it is not mistaken for a plain combined log;
  Traefik's JSON access logs continue to parse via the JSON-Lines parser.
- **`logatory agent`:** a tool-using investigation agent that runs a multi-step
  loop over your local data. `agent investigate <fingerprint>` triages a single
  tracked error; `agent ask "<question>"` answers a free-form question; `agent
  triage` surveys the whole dataset and returns a prioritized report (no
  fingerprint needed). The agent calls read-only DB tools to gather evidence
  before answering. `--max-steps` bounds the loop, `--verbose` shows each tool
  call, `--json` emits a machine-readable result for CI. Requires a tool-capable
  provider (`claude` or any OpenAI-compatible endpoint, including a local Ollama
  via `/v1`); other providers exit cleanly with guidance.
- **Agent tools:** beyond the per-error lookups, the agent can now call
  `get_summary` (dataset overview), `error_trend` (daily volume), `list_regressions`
  (errors that came back), `top_finding_rules` (most frequent/severe detections)
  and `get_findings_by_rule` (drill-down) — all read-only and size-bounded.
- **Native Ollama tool calling:** the `ollama` provider now implements
  `chat_with_tools` via its `/api/chat` endpoint, so the agent runs fully local
  without the OpenAI-compatible `/v1` detour. Requires a tool-capable model
  (e.g. `llama3.1`, `qwen2.5`, `mistral-nemo`).
- **Provider-neutral tool-use layer** (`llm/tools.py`, `llm/agent.py`): a small
  `Msg`/`ToolSpec`/`ToolCall`/`ToolResult` model with per-provider converters,
  plus a bounded agent loop. `chat_with_tools` is now implemented for the Claude
  and OpenAI-compatible clients.
- **Parsers:** Apache error log (classic 2.2 and 2.4 layouts, with log-level →
  severity mapping) and HAProxy HTTP log (syslog-prefix aware), both
  auto-detected. Apache *access* logs already parse via the combined-log parser.
- **Alert channels:** a `notify` subsystem with Slack, Discord, generic-webhook
  and e-mail (SMTP) notifiers. Configure any number under an `alerts:` section in
  `config.yaml`, each with its own `min_severity`; they fire on every realtime
  command automatically. `${ENV_VAR}` expansion keeps secrets out of the file.
- **`logatory alerts` CLI:** `alerts list` (show configured channels, secrets
  masked) and `alerts test` (send a sample finding to every channel).
- **Alert throttling:** an optional per-channel `cooldown` (seconds) suppresses
  repeats of the same finding (`rule_id` + `source`) within the window, taming
  alert storms. Only successful deliveries arm the timer.
- **Alert escalation:** optional per-channel `escalate_count` + `escalate_window`
  (seconds) hold an alert until the same finding occurs N times within the
  window, then fire once and reset — ideal for noisy rules where a single hit is
  noise but a rapid burst is real. Composes with `cooldown`.
- This changelog.
- CI test matrix now covers Python 3.13 and 3.14 (in addition to 3.11 and 3.12)
  on Linux, Windows and macOS; added the matching trove classifiers.
- CONTRIBUTING note documenting the harmless upstream `httpx`/`httpx2`
  Starlette `TestClient` deprecation warning.

### Changed
- The realtime alert path now routes through the `notify` dispatcher. The legacy
  `--alert-webhook` flag is unchanged and fires alongside configured channels.

### Fixed
- Use the non-deprecated `HTTP_422_UNPROCESSABLE_CONTENT` status constant in the
  event-ingest endpoint (silences a FastAPI/Starlette deprecation warning).

## [0.6.0] - 2026-06-12

A connectivity & extensibility release: six new log sources, two new parsers, and
a plugin system that can register parsers and adapters.

### Added
- **Source adapters:** Kubernetes (pod logs via `kubectl`), Windows Event Log
  (JSON export + live tailing), S3 / object storage (via the `aws` CLI), syslog
  listener (UDP/TCP, RFC 3164 & 5424), AWS CloudWatch Logs, GCP Cloud Logging.
- **Parsers:** logfmt (`key=value`) with format auto-detection; CEF / LEEF for
  security appliances.
- **Plugins** can now register custom parsers and source adapters, in addition to
  rules and PII patterns.
- A source-adapter registry as the single source of truth for adapter wiring.
- Structured `.xlsx` log parsing (header-row detection, typed columns).
- Full test coverage for the stdin and tail adapters (945 tests total).

### Changed
- Extracted an `HttpPollingAdapter` base class for HTTP-based sources.

### Fixed
- German phone-number PII pattern no longer matches date/time fragments.

### Docs
- Corrected README inaccuracies (rule operators, built-in rule IDs/severities, PII
  pattern list, LLM API-key environment variables).
- Added a troubleshooting note explaining why scans only appear in the dashboard
  when persisted with `--track-errors`.

## [0.5.0] - 2026-06-08

### Added
- Read `.xlsx` log files natively instead of garbling them as text.

### Changed
- Dropped the non-functional EVTX parser stub.

## [0.4.1] - 2026-05-23

### Added
- `Principal` abstraction in the web auth layer.

### Changed
- Numerous internal refactors: shared `SqliteRepository` base, `tail_pipeline`
  helper, `build_engine()`, `parse_lookback` time-spec helper, consolidated
  severity ordering, single `BUILTIN_RULES_DIR` constant.

### Fixed
- PII `dry-run` mode now truly leaves the text unchanged.

## [0.4.0] - 2026-05-22

### Added
- **Fleet** feature: scan/tail many targets at once — `fleet init` wizard,
  `fleet scan` (concurrent fan-out), `fleet tail` (realtime merge), `fleet list`
  (reachability check), browser-based config editor, dashboard target filter, and
  per-target persistence in SQLite.

## [0.3.0] - 2026-05-22

### Added
- Source adapters: Loki, Graylog, SSH remote host, systemd journald, Docker
  (scan + realtime tail), and OpenSearch realtime polling.

## [0.2.0] - 2026-05-22

### Added
- Web dashboard (`logatory serve`), REST API v1, Docker packaging, log-file upload
  page, false-positive suppression, Markdown export, and the plugin system.

[Unreleased]: https://github.com/T0nd3/logatory/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/T0nd3/logatory/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/T0nd3/logatory/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/T0nd3/logatory/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/T0nd3/logatory/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/T0nd3/logatory/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/T0nd3/logatory/releases/tag/v0.2.0
