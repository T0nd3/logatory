# Writing Logatory plugins

Logatory can be extended with **plugins** — plain Python files that contribute
custom detection rules, PII patterns, log-format parsers and source adapters
without touching the core code base.

A working, end-to-end example lives in [`plugins/example_plugin.py`](../plugins/example_plugin.py).

## Enabling plugins

Point `plugins_dir` at a directory in your `config.yaml`:

```yaml
plugins_dir: plugins/
```

At startup Logatory imports every `*.py` file in that directory (files whose
name starts with `_` are skipped) and calls the file's `register(registry)`
function. A plugin that raises during import or `register()` is logged and
skipped — one broken plugin never crashes the run.

## Anatomy of a plugin

The only requirement is a top-level `register` function that receives a
`PluginRegistry`:

```python
def register(registry) -> None:
    registry.add_rule({...})
    registry.add_pii_pattern(name="employee_id", pattern=r"\bEMP-\d{4,8}\b", prefix="employee")
    registry.add_parser("appliance", detect=_detect, factory=ApplianceParser)
    registry.add_adapter("demo-source", DemoAdapter)
```

## The registry API

### `add_rule(data: dict)`

Register a detection rule using the **same schema as the built-in YAML rules**.
Required keys: `id`, `title`, `level` (`low|medium|high|critical`). Conditions go
under `detection.match`:

```python
registry.add_rule({
    "id": "MY_RULE",
    "title": "My custom rule",
    "level": "high",
    "detection": {
        "match": [{"field": "message", "op": "contains", "value": "BADWORD"}]
    },
})
```

### `add_rule_dir(path)`

Register a whole directory of YAML rule files to be loaded:

```python
from pathlib import Path
registry.add_rule_dir(Path(__file__).parent / "my_rules")
```

### `add_pii_pattern(name, pattern, prefix="redacted")`

Add a custom redaction regex. A match for `pattern` is replaced with
`<prefix_…>`:

```python
registry.add_pii_pattern(name="employee_id", pattern=r"\bEMP-\d{4,8}\b", prefix="employee")
# "user EMP-12345 logged in" → "user <employee_…> logged in"
```

### `add_parser(name, detect, factory)`

Register a custom log-format parser. Because parsers are dispatched by name, a
plugin parser is added to a **global** registry the moment the plugin loads, so
format auto-detection picks it up everywhere.

- `name` — unique format name, e.g. `"appliance"`.
- `detect(sample_lines) -> bool` — receives a sample of stripped, non-empty
  lines and returns `True` when this parser should handle them. It runs **after**
  every built-in format check, just before the plaintext fallback, so built-in
  formats (JSON, syslog, nginx, …) always win. Keep `detect` strict (match a
  clear marker) so it never hijacks unrelated logs.
- `factory(source) -> BaseParser` — builds the parser for a given source name.

```python
from logatory.parsers.base import BaseParser
from logatory.models import Event, Severity

class ApplianceParser(BaseParser):
    def parse(self, line: str) -> Event | None:
        if not line.startswith("APP|"):
            return None
        _, ts, level, component, message = line.split("|", 4)
        return Event(raw=line, source=self.source, message=message, severity=Severity.INFO)

def _detect(lines): return bool(lines) and all(l.startswith("APP|") for l in lines)

registry.add_parser("appliance", detect=_detect, factory=ApplianceParser)
```

### `add_adapter(name, adapter_cls, fleet_target=False)`

Register a custom source adapter (an input). Like parsers, adapters are added to
a global registry immediately and can then be looked up by name.

- `name` — unique source name, e.g. `"kafka"`.
- `adapter_cls` — a `SourceAdapter` subclass that yields `Event` objects via an
  async `events()` generator.
- `fleet_target` — opt in (`True`) to make the adapter usable as a per-host
  fleet target. Defaults to `False`.

```python
from collections.abc import AsyncIterator
from logatory.adapters.base import SourceAdapter
from logatory.models import Event, Severity

class DemoAdapter(SourceAdapter):
    def __init__(self, source: str = "demo") -> None:
        self.source = source

    async def events(self) -> AsyncIterator[Event]:
        yield Event(raw="hello", source=self.source, message="hello", severity=Severity.INFO)

registry.add_adapter("demo-source", DemoAdapter)
```

## How contributions are used

| Contribution      | Wiring |
|-------------------|--------|
| Rules / rule dirs | Collected on the registry and handed to the rule engine by the CLI entry point. |
| PII patterns      | Compiled and merged into the `PIIRedactor`. |
| Parsers           | Registered globally; consulted by `FormatDetector` after the built-ins and built by `get_parser`. |
| Adapters          | Registered globally; looked up by name like any built-in source. |

## Tips

- Keep parser `detect` predicates **specific** — match a distinctive marker so
  they only fire on the intended format.
- Plugins are imported as ordinary modules, so you can define helper classes and
  functions alongside `register`.
- Validate your custom rules with `logatory rules validate <file>` and confirm
  loaded rules with `logatory rules list`.
