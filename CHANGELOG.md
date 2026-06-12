# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Use the non-deprecated `HTTP_422_UNPROCESSABLE_CONTENT` status constant in the
  event-ingest endpoint (silences a FastAPI/Starlette deprecation warning).

### Added
- This changelog.

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
