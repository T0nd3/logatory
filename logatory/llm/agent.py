"""A minimal, provider-neutral tool-using agent loop.

The agent drives a conversation with a tool-capable LLM client: it offers a set
of :class:`Tool` s, lets the model decide which to call, executes them locally,
feeds the results back, and repeats until the model answers in plain text or the
step budget is exhausted.  Everything is read-only and bounded by design.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .tools import Msg, ToolResult, ToolSpec

if TYPE_CHECKING:
    from .base import AbstractLLMClient
    from .tools import ToolCall


@dataclass
class Tool:
    """A tool the agent can run: its public spec plus the local handler."""

    spec: ToolSpec
    handler: Callable[..., str]


@dataclass
class AgentStep:
    """One recorded step: a tool invocation or the final answer."""

    kind: str  # "tool_call" | "answer"
    name: str = ""
    arguments: dict[str, Any] | None = None
    result: str = ""


@dataclass
class AgentResult:
    answer: str
    steps: list[AgentStep] = field(default_factory=list)
    iterations: int = 0
    truncated: bool = False  # hit the step budget before a clean answer


class Agent:
    def __init__(
        self,
        client: AbstractLLMClient,
        tools: list[Tool],
        *,
        system: str = "",
        max_iterations: int = 8,
    ) -> None:
        self.client = client
        self.tools = {t.spec.name: t for t in tools}
        self.specs = [t.spec for t in tools]
        self.system = system
        self.max_iterations = max(1, max_iterations)

    def run(self, task: str) -> AgentResult:
        messages: list[Msg] = [Msg(role="user", text=task)]
        steps: list[AgentStep] = []

        for i in range(1, self.max_iterations + 1):
            turn = self.client.chat_with_tools(messages, self.specs, system=self.system)

            if not turn.wants_tools:
                steps.append(AgentStep(kind="answer", result=turn.text))
                return AgentResult(answer=turn.text, steps=steps, iterations=i)

            messages.append(Msg(role="assistant", text=turn.text, tool_calls=turn.tool_calls))
            results: list[ToolResult] = []
            for call in turn.tool_calls:
                out = self._run_tool(call)
                steps.append(
                    AgentStep(
                        kind="tool_call", name=call.name, arguments=call.arguments, result=out
                    )
                )
                results.append(ToolResult(id=call.id, name=call.name, content=out))
            messages.append(Msg(role="user", tool_results=results))

        # Step budget exhausted while the model still wanted tools. Force a final
        # answer by asking once more with no tools available.
        messages.append(
            Msg(
                role="user",
                text="You have reached the investigation step limit. "
                "Give your best final answer now using the evidence gathered so far.",
            )
        )
        final = self.client.chat_with_tools(messages, [], system=self.system)
        steps.append(AgentStep(kind="answer", result=final.text))
        return AgentResult(
            answer=final.text, steps=steps, iterations=self.max_iterations, truncated=True
        )

    def _run_tool(self, call: ToolCall) -> str:
        tool = self.tools.get(call.name)
        if tool is None:
            return f"ERROR: unknown tool '{call.name}'"
        try:
            return tool.handler(**call.arguments)
        except Exception as e:
            return f"ERROR: tool '{call.name}' failed: {e}"
