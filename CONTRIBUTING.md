# Contributing to Logatory

Thanks for your interest in improving Logatory! This document covers how to set
up a development environment, run the checks, and submit changes.

## Development setup

Logatory targets **Python 3.11+**.

```bash
# Clone
git clone https://github.com/T0nd3/logatory.git
cd logatory

# Install in editable mode with all optional features + dev tools
pip install -e '.[web,opensearch,xlsx,claude,embed,dev]'
```

The optional extras are independent — for most work `.[dev,web]` is enough. The
full set above is only needed when touching the OpenSearch, xlsx, Claude or
embedding code paths.

## Running the checks

CI runs three things on Linux, Windows and macOS (Python 3.11 and 3.12). Run
them locally before opening a pull request:

```bash
pytest                  # test suite
ruff check .            # linter
ruff format --check .   # formatting
```

`ruff format .` (without `--check`) applies the formatting. All ruff
configuration lives in `pyproject.toml`.

## Code style

- Line length 99, double quotes — enforced by `ruff format`.
- Type hints throughout; modules use `from __future__ import annotations`.
- Keep the core library (`logatory/`) free of CLI/HTTP concerns — see
  Architecture below.

## Architecture

Logatory follows a **library-first** design:

- `logatory/` is a pure Python library — all analysis logic lives here.
- `logatory/cli/` (Typer) and `logatory/web/` (FastAPI) are thin wrappers that
  call the library; they contain no analysis logic of their own.
- The **PII redactor runs directly after parsing** — no downstream component
  (rules, stats, LLM, storage) ever sees raw PII.
- Storage goes through the repository pattern in `logatory/storage/`.

New analysis features belong in the library; the CLI and web layers only
expose them.

## Project layout

```
logatory/          Core library
  adapters/            File, stdin, tail, OpenSearch event adapters
  anomaly/             Statistical baseline and Z-score detector
  errors/              Error fingerprinting and grouping
  export/              Markdown report generator
  llm/                 LLM client factory and prompt templates
  parsers/             Syslog, Nginx, JSON Lines, plaintext parsers
  pii/                 PII patterns and redactor
  plugins/             Plugin loader and registry
  rules/               Rule engine, YAML loader, Sigma converter
  storage/             SQLite repositories (findings, errors, baseline, dismiss)
  web/                 FastAPI app, HTMX routes, Jinja2 templates
  cli/                 Typer CLI commands (scan, tail, serve, …)

tests/                 pytest test suite
plugins/               Example plugin (add your own here)
config.yaml.example    Annotated configuration template
Dockerfile             Multi-stage production image
docker-compose.yml     Compose stack with named volume
```

## Submitting changes

1. Fork the repository and create a branch off `master`.
2. Make your change; add or update tests to cover it.
3. Make sure `pytest`, `ruff check .` and `ruff format --check .` all pass.
4. Open a pull request against `master` with a clear description of what
   changed and why.

## Reporting bugs and requesting features

Use the issue templates — they prompt for the details needed to act on a
report. For security vulnerabilities, **do not open a public issue**; see
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE), the same license as the project.
