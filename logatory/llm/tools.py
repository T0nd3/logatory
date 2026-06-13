"""Provider-neutral data model for tool-using (agentic) LLM calls.

The agent loop and the rest of the codebase speak only in these neutral types.
Each concrete client (Claude, OpenAI-compatible) translates them to/from its own
wire format via the converter functions here, which are pure and unit-testable
without any network or SDK.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Tool definitions and call/return values
# ---------------------------------------------------------------------------


@dataclass
class ToolSpec:
    """Declares a tool the model may call: name, description and a JSON schema."""

    name: str
    description: str
    input_schema: dict[str, Any]

    def to_anthropic(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def to_openai(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }


@dataclass
class ToolCall:
    """A model's request to invoke a tool with parsed arguments."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """The string result of running a tool, paired back to its call id."""

    id: str
    name: str
    content: str


@dataclass
class AssistantTurn:
    """One model response: free text and/or a set of tool calls."""

    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


@dataclass
class Msg:
    """A neutral conversation message.

    A plain message carries ``text``.  An assistant message that requested tools
    carries ``tool_calls``.  A message returning tool output carries
    ``tool_results``.
    """

    role: str  # "user" | "assistant"
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Anthropic <-> neutral
# ---------------------------------------------------------------------------


def messages_to_anthropic(messages: list[Msg]) -> list[dict[str, Any]]:
    """Convert neutral messages to the Anthropic Messages API shape."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.tool_results:
            out.append(
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": r.id, "content": r.content}
                        for r in m.tool_results
                    ],
                }
            )
            continue
        if m.role == "assistant" and m.tool_calls:
            content: list[dict[str, Any]] = []
            if m.text:
                content.append({"type": "text", "text": m.text})
            for c in m.tool_calls:
                content.append(
                    {"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments}
                )
            out.append({"role": "assistant", "content": content})
            continue
        out.append({"role": m.role, "content": m.text})
    return out


def parse_anthropic_response(content_blocks: list[Any], stop_reason: str = "") -> AssistantTurn:
    """Parse Anthropic response content blocks into an :class:`AssistantTurn`.

    Works on the SDK's block objects (attribute access ``.type``/``.text``/
    ``.id``/``.name``/``.input``); tests feed simple stand-ins with the same
    attributes, so this stays SDK-free.
    """
    text_parts: list[str] = []
    calls: list[ToolCall] = []
    for block in content_blocks:
        btype = getattr(block, "type", None)
        if btype == "text":
            text_parts.append(getattr(block, "text", ""))
        elif btype == "tool_use":
            calls.append(
                ToolCall(
                    id=getattr(block, "id", ""),
                    name=getattr(block, "name", ""),
                    arguments=dict(getattr(block, "input", {}) or {}),
                )
            )
    return AssistantTurn(text="".join(text_parts), tool_calls=calls, stop_reason=stop_reason)


# ---------------------------------------------------------------------------
# OpenAI <-> neutral
# ---------------------------------------------------------------------------


def messages_to_openai(messages: list[Msg], system: str | None = None) -> list[dict[str, Any]]:
    """Convert neutral messages to the OpenAI chat-completions shape."""
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for m in messages:
        if m.tool_results:
            for r in m.tool_results:
                out.append({"role": "tool", "tool_call_id": r.id, "content": r.content})
            continue
        if m.role == "assistant" and m.tool_calls:
            out.append(
                {
                    "role": "assistant",
                    "content": m.text or None,
                    "tool_calls": [
                        {
                            "id": c.id,
                            "type": "function",
                            "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
                        }
                        for c in m.tool_calls
                    ],
                }
            )
            continue
        out.append({"role": m.role, "content": m.text})
    return out


def parse_openai_message(message: dict[str, Any]) -> AssistantTurn:
    """Parse one OpenAI ``choices[].message`` dict into an :class:`AssistantTurn`."""
    text = message.get("content") or ""
    calls: list[ToolCall] = []
    for tc in message.get("tool_calls") or []:
        fn = tc.get("function", {})
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args)
        except (json.JSONDecodeError, TypeError):
            args = {}
        calls.append(ToolCall(id=tc.get("id", ""), name=fn.get("name", ""), arguments=args))
    return AssistantTurn(text=text, tool_calls=calls)


# ---------------------------------------------------------------------------
# Ollama <-> neutral  (native /api/chat tool calling)
# ---------------------------------------------------------------------------
#
# Ollama is OpenAI-ish but with two differences we must handle:
#   * tool calls carry no ``id`` — results are matched back by tool *name* via
#     the ``tool_name`` field on the tool message, so we synthesize ids only for
#     the neutral model and never send them back;
#   * tool-call ``arguments`` are already a JSON object, not a JSON string.


def messages_to_ollama(messages: list[Msg], system: str | None = None) -> list[dict[str, Any]]:
    """Convert neutral messages to the Ollama ``/api/chat`` shape."""
    out: list[dict[str, Any]] = []
    if system:
        out.append({"role": "system", "content": system})
    for m in messages:
        if m.tool_results:
            for r in m.tool_results:
                out.append({"role": "tool", "content": r.content, "tool_name": r.name})
            continue
        if m.role == "assistant" and m.tool_calls:
            out.append(
                {
                    "role": "assistant",
                    "content": m.text or "",
                    "tool_calls": [
                        {"function": {"name": c.name, "arguments": c.arguments}}
                        for c in m.tool_calls
                    ],
                }
            )
            continue
        out.append({"role": m.role, "content": m.text})
    return out


def parse_ollama_message(message: dict[str, Any]) -> AssistantTurn:
    """Parse one Ollama ``message`` dict into an :class:`AssistantTurn`."""
    text = message.get("content") or ""
    calls: list[ToolCall] = []
    for i, tc in enumerate(message.get("tool_calls") or []):
        fn = tc.get("function", {})
        args = fn.get("arguments")
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except (json.JSONDecodeError, TypeError):
                args = {}
        calls.append(ToolCall(id=f"call_{i}", name=fn.get("name", ""), arguments=dict(args or {})))
    return AssistantTurn(text=text, tool_calls=calls)
