"""Tests for the tool-using agent layer.

Covers the provider-neutral tool data model and its converters, the agent loop
(tool execution, truncation, error handling), the read-only investigation tools
against a temp SQLite DB, and the `logatory agent` CLI commands. Everything runs
offline: LLM clients are replaced by scripted fakes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from logatory.cli import agent_cmd
from logatory.cli.main import app as main_app
from logatory.llm.agent import Agent
from logatory.llm.agent_tools import build_investigation_tools
from logatory.llm.base import AbstractLLMClient
from logatory.llm.tools import (
    AssistantTurn,
    Msg,
    ToolCall,
    ToolResult,
    ToolSpec,
    messages_to_anthropic,
    messages_to_openai,
    parse_anthropic_response,
    parse_openai_message,
)
from logatory.models import Finding, FindingSeverity
from logatory.storage.errors_repo import ErrorsRepository
from logatory.storage.findings_repo import FindingsRepository

runner = CliRunner()
_T0 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Fake clients
# ---------------------------------------------------------------------------


class ScriptedClient(AbstractLLMClient):
    """Replays a fixed sequence of AssistantTurns, one per chat_with_tools call."""

    supports_tools = True
    is_cloud = False
    provider_name = "scripted"

    def __init__(self, turns: list[AssistantTurn]) -> None:
        self._turns = list(turns)
        self.calls: list[tuple[list[Msg], list[ToolSpec]]] = []

    def is_available(self) -> bool:
        return True

    def generate(self, prompt, stream=True):  # pragma: no cover - unused
        yield ""

    def chat_with_tools(self, messages, tools, system=""):
        self.calls.append((list(messages), list(tools)))
        if self._turns:
            return self._turns.pop(0)
        return AssistantTurn(text="(exhausted)")


class LoopingClient(AbstractLLMClient):
    """Always asks for a tool while tools are offered; answers when they aren't.

    This forces the agent to hit its step budget and take the forced-final path.
    """

    supports_tools = True
    is_cloud = False
    provider_name = "looping"

    def is_available(self) -> bool:
        return True

    def generate(self, prompt, stream=True):  # pragma: no cover - unused
        yield ""

    def chat_with_tools(self, messages, tools, system=""):
        if tools:
            return AssistantTurn(tool_calls=[ToolCall(id="x", name="noop", arguments={})])
        return AssistantTurn(text="forced final answer")


def _spec(name: str = "noop") -> ToolSpec:
    return ToolSpec(name=name, description="d", input_schema={"type": "object", "properties": {}})


def _tool(name: str, handler):
    from logatory.llm.agent import Tool

    return Tool(spec=_spec(name), handler=handler)


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------


def test_agent_executes_tool_then_answers():
    seen: dict = {}

    def handler(**kwargs):
        seen.update(kwargs)
        return "tool-output"

    client = ScriptedClient(
        [
            AssistantTurn(tool_calls=[ToolCall(id="c1", name="lookup", arguments={"q": "x"})]),
            AssistantTurn(text="final answer"),
        ]
    )
    agent = Agent(client, [_tool("lookup", handler)], system="sys", max_iterations=8)
    result = agent.run("do it")

    assert result.answer == "final answer"
    assert result.truncated is False
    assert result.iterations == 2
    assert seen == {"q": "x"}
    # one tool_call step + one answer step
    kinds = [s.kind for s in result.steps]
    assert kinds == ["tool_call", "answer"]
    assert result.steps[0].result == "tool-output"
    # the system prompt is forwarded to the client
    assert client.calls[0][0][0].text == "do it"


def test_agent_truncates_at_step_budget():
    agent = Agent(LoopingClient(), [_tool("noop", lambda **_: "x")], max_iterations=3)
    result = agent.run("loop forever")

    assert result.truncated is True
    assert result.iterations == 3
    assert result.answer == "forced final answer"
    # 3 tool calls + final forced answer
    assert sum(s.kind == "tool_call" for s in result.steps) == 3


def test_agent_handles_unknown_tool():
    client = ScriptedClient(
        [
            AssistantTurn(tool_calls=[ToolCall(id="c1", name="ghost", arguments={})]),
            AssistantTurn(text="done"),
        ]
    )
    agent = Agent(client, [_tool("real", lambda **_: "ok")])
    result = agent.run("q")
    assert "unknown tool 'ghost'" in result.steps[0].result


def test_agent_handles_tool_exception():
    def boom(**_):
        raise ValueError("kaboom")

    client = ScriptedClient(
        [
            AssistantTurn(tool_calls=[ToolCall(id="c1", name="boom", arguments={})]),
            AssistantTurn(text="recovered"),
        ]
    )
    agent = Agent(client, [_tool("boom", boom)])
    result = agent.run("q")
    assert "tool 'boom' failed: kaboom" in result.steps[0].result
    assert result.answer == "recovered"


def test_agent_max_iterations_floored_to_one():
    agent = Agent(ScriptedClient([]), [], max_iterations=0)
    assert agent.max_iterations == 1


# ---------------------------------------------------------------------------
# Converters: OpenAI
# ---------------------------------------------------------------------------


def test_messages_to_openai_roundtrip_shapes():
    msgs = [
        Msg(role="user", text="hi"),
        Msg(
            role="assistant",
            text="",
            tool_calls=[ToolCall(id="c1", name="lookup", arguments={"q": "x"})],
        ),
        Msg(role="user", tool_results=[ToolResult(id="c1", name="lookup", content="res")]),
    ]
    out = messages_to_openai(msgs, system="be terse")
    assert out[0] == {"role": "system", "content": "be terse"}
    assert out[1] == {"role": "user", "content": "hi"}
    assert out[2]["role"] == "assistant"
    assert out[2]["content"] is None
    tc = out[2]["tool_calls"][0]
    assert tc["id"] == "c1"
    assert tc["function"]["name"] == "lookup"
    assert tc["function"]["arguments"] == '{"q": "x"}'
    assert out[3] == {"role": "tool", "tool_call_id": "c1", "content": "res"}


def test_parse_openai_message_with_tool_calls():
    message = {
        "content": None,
        "tool_calls": [
            {"id": "c9", "function": {"name": "get_error", "arguments": '{"fingerprint": "ab"}'}}
        ],
    }
    turn = parse_openai_message(message)
    assert turn.wants_tools
    assert turn.tool_calls[0].name == "get_error"
    assert turn.tool_calls[0].arguments == {"fingerprint": "ab"}


def test_parse_openai_message_bad_arguments_fall_back_to_empty():
    message = {
        "content": "",
        "tool_calls": [{"id": "c1", "function": {"name": "x", "arguments": "not-json"}}],
    }
    turn = parse_openai_message(message)
    assert turn.tool_calls[0].arguments == {}


def test_parse_openai_message_plain_text():
    turn = parse_openai_message({"content": "just text"})
    assert turn.text == "just text"
    assert not turn.wants_tools


# ---------------------------------------------------------------------------
# Converters: Anthropic
# ---------------------------------------------------------------------------


def test_messages_to_anthropic_shapes():
    msgs = [
        Msg(role="user", text="hi"),
        Msg(
            role="assistant",
            text="thinking",
            tool_calls=[ToolCall(id="c1", name="lookup", arguments={"q": "x"})],
        ),
        Msg(role="user", tool_results=[ToolResult(id="c1", name="lookup", content="res")]),
    ]
    out = messages_to_anthropic(msgs)
    assert out[0] == {"role": "user", "content": "hi"}
    assert out[1]["role"] == "assistant"
    blocks = out[1]["content"]
    assert blocks[0] == {"type": "text", "text": "thinking"}
    assert blocks[1] == {"type": "tool_use", "id": "c1", "name": "lookup", "input": {"q": "x"}}
    res_block = out[2]["content"][0]
    assert res_block == {"type": "tool_result", "tool_use_id": "c1", "content": "res"}


def test_parse_anthropic_response_mixed_blocks():
    blocks = [
        SimpleNamespace(type="text", text="here is "),
        SimpleNamespace(type="text", text="my plan"),
        SimpleNamespace(type="tool_use", id="t1", name="get_error", input={"fingerprint": "ab"}),
    ]
    turn = parse_anthropic_response(blocks, stop_reason="tool_use")
    assert turn.text == "here is my plan"
    assert turn.stop_reason == "tool_use"
    assert turn.tool_calls[0].name == "get_error"
    assert turn.tool_calls[0].arguments == {"fingerprint": "ab"}


def test_tool_spec_serialization():
    spec = _spec("foo")
    a = spec.to_anthropic()
    assert set(a) == {"name", "description", "input_schema"}
    o = spec.to_openai()
    assert o["type"] == "function"
    assert o["function"]["name"] == "foo"
    assert o["function"]["parameters"] == spec.input_schema


# ---------------------------------------------------------------------------
# Converters: Ollama (native /api/chat)
# ---------------------------------------------------------------------------


def test_messages_to_ollama_shapes():
    from logatory.llm.tools import messages_to_ollama

    msgs = [
        Msg(role="user", text="hi"),
        Msg(
            role="assistant",
            text="thinking",
            tool_calls=[ToolCall(id="call_0", name="lookup", arguments={"q": "x"})],
        ),
        Msg(role="user", tool_results=[ToolResult(id="call_0", name="lookup", content="res")]),
    ]
    out = messages_to_ollama(msgs, system="be terse")
    assert out[0] == {"role": "system", "content": "be terse"}
    assert out[1] == {"role": "user", "content": "hi"}
    assert out[2]["role"] == "assistant"
    # arguments stay a dict (not a JSON string), and no id is sent back
    assert out[2]["tool_calls"][0] == {"function": {"name": "lookup", "arguments": {"q": "x"}}}
    # tool results are matched back by name via tool_name
    assert out[3] == {"role": "tool", "content": "res", "tool_name": "lookup"}


def test_parse_ollama_message_with_tool_calls():
    from logatory.llm.tools import parse_ollama_message

    message = {
        "content": "",
        "tool_calls": [
            {"function": {"name": "get_error", "arguments": {"fingerprint": "ab"}}},
            {"function": {"name": "list_errors", "arguments": {"limit": 3}}},
        ],
    }
    turn = parse_ollama_message(message)
    assert turn.wants_tools
    # ids are synthesized positionally since Ollama omits them
    assert [c.id for c in turn.tool_calls] == ["call_0", "call_1"]
    assert turn.tool_calls[0].arguments == {"fingerprint": "ab"}


def test_parse_ollama_message_string_arguments_fallback():
    from logatory.llm.tools import parse_ollama_message

    # Some models emit arguments as a JSON string; handle both.
    good = parse_ollama_message(
        {"tool_calls": [{"function": {"name": "x", "arguments": '{"a": 1}'}}]}
    )
    assert good.tool_calls[0].arguments == {"a": 1}
    bad = parse_ollama_message(
        {"tool_calls": [{"function": {"name": "x", "arguments": "not-json"}}]}
    )
    assert bad.tool_calls[0].arguments == {}


def test_ollama_client_supports_tools_and_chat(monkeypatch):
    import json
    import urllib.request

    from logatory.llm.client import OllamaClient

    assert OllamaClient.supports_tools is True

    captured: dict = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self):
            return json.dumps(
                {
                    "message": {
                        "content": "",
                        "tool_calls": [{"function": {"name": "get_summary", "arguments": {}}}],
                    }
                }
            ).encode()

    def fake_urlopen(req, *a, **kw):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data)
        return FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = OllamaClient(model="llama3.1")
    turn = client.chat_with_tools(
        [Msg(role="user", text="triage")], [_spec("get_summary")], system="sys"
    )
    assert captured["url"].endswith("/api/chat")
    assert captured["body"]["tools"][0]["function"]["name"] == "get_summary"
    assert captured["body"]["messages"][0] == {"role": "system", "content": "sys"}
    assert turn.tool_calls[0].name == "get_summary"


def test_ollama_native_agent_loop_end_to_end(monkeypatch):
    """Drive the full agent loop through a real OllamaClient with scripted HTTP."""
    import json
    import urllib.request

    from logatory.llm.client import OllamaClient

    responses = [
        # 1st turn: model asks to call a tool
        {
            "message": {
                "content": "",
                "tool_calls": [{"function": {"name": "ping", "arguments": {}}}],
            }
        },
        # 2nd turn: model answers in plain text
        {"message": {"content": "native ollama done", "tool_calls": []}},
    ]

    class FakeResp:
        def __init__(self, body):
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def read(self):
            return json.dumps(self._body).encode()

    def fake_urlopen(req, *a, **kw):
        return FakeResp(responses.pop(0))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    calls: list = []
    agent = Agent(
        OllamaClient(model="llama3.1"), [_tool("ping", lambda **_: calls.append(1) or "pong")]
    )
    result = agent.run("go")
    assert result.answer == "native ollama done"
    assert result.truncated is False
    assert calls == [1]  # the tool ran exactly once


# ---------------------------------------------------------------------------
# Investigation tools against a real temp DB
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded_db(tmp_path: Path) -> Path:
    db = tmp_path / "logatory.db"
    with ErrorsRepository(db) as repo:
        repo.upsert(
            fingerprint="fp1",
            error_type="ConnectionError",
            normalized_msg="ConnectionError: refused",
            severity="error",
            source="api",
            timestamp=_T0,
            sample="conn refused to db",
            stack_trace="Traceback...\nConnectionError: refused",
            stack_lang="python",
        )
        repo.upsert(
            fingerprint="fp2",
            error_type="TimeoutError",
            normalized_msg="TimeoutError: slow",
            severity="warning",
            source="worker",
            timestamp=_T0,
            sample="timeout",
        )
    with FindingsRepository(db) as frepo:
        frepo.add_findings(
            [
                Finding(
                    rule_id="net.refused",
                    severity=FindingSeverity.HIGH,
                    message="connection refused spike",
                    source="api",
                    timestamp=_T0,
                )
            ]
        )
    return db


def _call(tools, name, **kwargs):
    tool = next(t for t in tools if t.spec.name == name)
    return tool.handler(**kwargs)


def test_get_error_tool(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    data = json.loads(_call(tools, "get_error", fingerprint="fp1"))
    assert data["error_type"] == "ConnectionError"
    assert data["count"] == 1


def test_get_error_tool_missing(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    data = json.loads(_call(tools, "get_error", fingerprint="nope"))
    assert "error" in data


def test_get_occurrences_tool_truncates(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    rows = json.loads(_call(tools, "get_occurrences", fingerprint="fp1", limit=5))
    assert rows
    assert rows[0]["stack_trace"].startswith("Traceback")


def test_list_errors_tool(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    rows = json.loads(_call(tools, "list_errors", limit=10))
    fps = {r["fingerprint"] for r in rows}
    assert {"fp1", "fp2"} <= fps


def test_search_findings_tool(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    rows = json.loads(_call(tools, "search_findings", keyword="refused"))
    assert rows
    assert rows[0]["rule_id"] == "net.refused"


def test_search_findings_missing_table(tmp_path):
    import json

    # Fresh DB with no findings table created yet.
    db = tmp_path / "empty.db"
    db.touch()
    tools = build_investigation_tools(db)
    assert json.loads(_call(tools, "search_findings", keyword="x")) == []


def test_get_summary_tool(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    data = json.loads(_call(tools, "get_summary"))
    assert data["errors"]["total_error_types"] == 2
    assert data["findings"]["total"] == 1
    assert data["errors"]["by_severity"].get("error") == 1


def test_top_finding_rules_tool(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    rows = json.loads(_call(tools, "top_finding_rules", sort="severity", limit=5))
    assert rows
    assert rows[0]["rule_id"] == "net.refused"
    assert rows[0]["count"] == 1


def test_get_findings_by_rule_tool(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    rows = json.loads(_call(tools, "get_findings_by_rule", rule_id="net.refused"))
    assert rows
    assert rows[0]["message"] == "connection refused spike"


def test_error_trend_and_regressions_are_lists(seeded_db):
    import json

    tools = build_investigation_tools(seeded_db)
    assert isinstance(json.loads(_call(tools, "error_trend", days=14)), list)
    assert isinstance(json.loads(_call(tools, "list_regressions", gap_hours=24)), list)


def test_error_trend_counts_recent_occurrences(tmp_path):
    import json

    db = tmp_path / "recent.db"
    now = datetime.now(UTC)
    with ErrorsRepository(db) as repo:
        repo.upsert(
            fingerprint="fpR",
            error_type="ValueError",
            normalized_msg="boom",
            severity="error",
            source="api",
            timestamp=now,
            sample="boom",
        )
    tools = build_investigation_tools(db)
    rows = json.loads(_call(tools, "error_trend", days=14))
    assert rows  # at least today's bucket
    assert any(r["count"] >= 1 for r in rows)


def test_list_regressions_detects_reappearance(tmp_path):
    import json

    db = tmp_path / "regress.db"
    now = datetime.now(UTC)
    with ErrorsRepository(db) as repo:
        # First seen 48h ago, then seen again now -> a regression.
        repo.upsert(
            fingerprint="fpG",
            error_type="TimeoutError",
            normalized_msg="slow",
            severity="warning",
            source="worker",
            timestamp=now - timedelta(hours=48),
            sample="slow",
        )
        repo.upsert(
            fingerprint="fpG",
            error_type="TimeoutError",
            normalized_msg="slow",
            severity="warning",
            source="worker",
            timestamp=now,
            sample="slow again",
        )
    tools = build_investigation_tools(db)
    rows = json.loads(_call(tools, "list_regressions", gap_hours=24))
    assert any(r["fingerprint"] == "fpG" for r in rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class _CliClient(AbstractLLMClient):
    provider_name = "fake"

    def __init__(self, *, supports, available=True, cloud=False, answer="ANSWER"):
        self.supports_tools = supports
        self.is_cloud = cloud
        self._available = available
        self._answer = answer

    def is_available(self):
        return self._available

    def generate(self, prompt, stream=True):  # pragma: no cover - unused
        yield ""

    def chat_with_tools(self, messages, tools, system=""):
        return AssistantTurn(text=self._answer)


def _seed_one_error(db: Path) -> None:
    with ErrorsRepository(db) as repo:
        repo.upsert(
            fingerprint="fpCLI",
            error_type="ConnectionError",
            normalized_msg="x",
            severity="error",
            source="api",
            timestamp=_T0,
            sample="s",
        )


def test_cli_investigate_happy_path(tmp_path, monkeypatch):
    db = tmp_path / "logatory.db"
    _seed_one_error(db)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    monkeypatch.setattr(
        agent_cmd, "make_llm_client", lambda _: _CliClient(supports=True, answer="ROOT CAUSE")
    )
    res = runner.invoke(main_app, ["agent", "investigate", "fpCLI", "--config", str(cfg_file)])
    assert res.exit_code == 0, res.output
    assert "ROOT CAUSE" in res.output


def test_cli_investigate_unknown_fingerprint(tmp_path, monkeypatch):
    db = tmp_path / "logatory.db"
    _seed_one_error(db)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    monkeypatch.setattr(agent_cmd, "make_llm_client", lambda _: _CliClient(supports=True))
    res = runner.invoke(main_app, ["agent", "investigate", "ghost", "--config", str(cfg_file)])
    assert res.exit_code == 1
    assert "not found" in res.output


def test_cli_agent_requires_tool_support(tmp_path, monkeypatch):
    db = tmp_path / "logatory.db"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    monkeypatch.setattr(agent_cmd, "make_llm_client", lambda _: _CliClient(supports=False))
    res = runner.invoke(main_app, ["agent", "ask", "what broke?", "--config", str(cfg_file)])
    assert res.exit_code == 1
    assert "does not support tool use" in res.output


def test_cli_agent_unreachable_provider(tmp_path, monkeypatch):
    db = tmp_path / "logatory.db"
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    monkeypatch.setattr(
        agent_cmd,
        "make_llm_client",
        lambda _: _CliClient(supports=True, available=False),
    )
    res = runner.invoke(main_app, ["agent", "ask", "hi", "--config", str(cfg_file)])
    assert res.exit_code == 1
    assert "not reachable" in res.output


def test_cli_agent_ask_verbose_shows_steps(tmp_path, monkeypatch):
    db = tmp_path / "logatory.db"
    _seed_one_error(db)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    # A client that calls one tool then answers, so verbose output has a step.
    turns = [
        AssistantTurn(tool_calls=[ToolCall(id="c1", name="list_errors", arguments={"limit": 5})]),
        AssistantTurn(text="DONE"),
    ]

    class _Scripted(ScriptedClient):
        is_cloud = True  # also exercises the cloud warning

    monkeypatch.setattr(agent_cmd, "make_llm_client", lambda _: _Scripted(turns))
    res = runner.invoke(
        main_app,
        ["agent", "ask", "list everything", "--config", str(cfg_file), "--verbose"],
    )
    assert res.exit_code == 0, res.output
    assert "list_errors" in res.output
    assert "DONE" in res.output
    assert "Cloud provider" in res.output


def test_cli_triage_happy_path(tmp_path, monkeypatch):
    db = tmp_path / "logatory.db"
    _seed_one_error(db)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    monkeypatch.setattr(
        agent_cmd, "make_llm_client", lambda _: _CliClient(supports=True, answer="PRIORITIZED")
    )
    res = runner.invoke(main_app, ["agent", "triage", "--config", str(cfg_file)])
    assert res.exit_code == 0, res.output
    assert "PRIORITIZED" in res.output


def test_cli_json_output_is_parseable(tmp_path, monkeypatch):
    import json

    db = tmp_path / "logatory.db"
    _seed_one_error(db)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(f"db_path: {db}\n")

    turns = [
        AssistantTurn(tool_calls=[ToolCall(id="c1", name="get_summary", arguments={})]),
        AssistantTurn(text="ALL CLEAR"),
    ]
    monkeypatch.setattr(agent_cmd, "make_llm_client", lambda _: ScriptedClient(turns))
    res = runner.invoke(main_app, ["agent", "triage", "--config", str(cfg_file), "--json"])
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output.strip())
    assert payload["answer"] == "ALL CLEAR"
    assert payload["truncated"] is False
    assert any(s["name"] == "get_summary" for s in payload["steps"])
