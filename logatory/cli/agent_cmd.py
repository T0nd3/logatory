"""`logatory agent` — a tool-using investigation agent over your local data.

Unlike `logatory llm ask` (single-shot RAG), the agent runs a multi-step loop:
it decides which read-only DB tools to call, reads the results, and keeps going
until it can answer.  It needs a provider that supports function/tool calling
(Claude or any OpenAI-compatible endpoint, including a local Ollama via /v1).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Optional

import typer

from logatory.config import Config
from logatory.llm.agent import Agent, AgentResult
from logatory.llm.agent_tools import build_investigation_tools
from logatory.llm.base import AbstractLLMClient
from logatory.llm.factory import make_llm_client
from logatory.storage.errors_repo import ErrorsRepository

app = typer.Typer(
    help="Tool-using investigation agent (multi-step, read-only) over your local data."
)

_CLOUD_WARNING = "  [!] Cloud provider — log data (PII-redacted) will be sent to an external API."

_SYSTEM_PROMPT = (
    "You are Logatory's log triage agent. You investigate errors and findings in a "
    "local SQLite database using the read-only tools provided. Work step by step: "
    "call tools to gather concrete evidence (error records, recent occurrences with "
    "stack traces, related errors, matching findings) before drawing conclusions. "
    "Do not invent data — only rely on what the tools return. When you have enough "
    "evidence, give a concise, well-structured answer: the most likely root cause, "
    "the supporting evidence, and a short list of concrete next steps. If the tools "
    "return nothing useful, say so plainly instead of guessing."
)


def _prepare_client(cfg: Config) -> AbstractLLMClient:
    """Build the LLM client and fail fast unless it can actually run the agent."""
    client = make_llm_client(cfg.llm)

    if not client.supports_tools:
        typer.echo(
            typer.style(
                f"  Provider '{cfg.llm.provider}' does not support tool use (agent mode).",
                fg=typer.colors.RED,
            ),
            err=True,
        )
        typer.echo(
            "  Use a tool-capable provider: 'claude' or an OpenAI-compatible endpoint\n"
            "  (set provider: openai_compat — this also covers a local Ollama via /v1).",
            err=True,
        )
        raise typer.Exit(1)

    if client.is_cloud:
        typer.echo(typer.style(_CLOUD_WARNING, fg=typer.colors.YELLOW), err=True)

    if not client.is_available():
        typer.echo(
            f"  LLM provider '{cfg.llm.provider}' is not reachable.\n"
            "  Check your endpoint and API key (or run: ollama serve).",
            err=True,
        )
        raise typer.Exit(1)

    return client


def _render(result: AgentResult, *, verbose: bool, as_json: bool = False) -> None:
    """Print the agent's tool steps (optionally) and its final answer."""
    if as_json:
        payload = {
            "answer": result.answer,
            "truncated": result.truncated,
            "iterations": result.iterations,
            "steps": [
                {
                    "kind": s.kind,
                    "name": s.name,
                    "arguments": s.arguments,
                    "result": s.result,
                }
                for s in result.steps
            ],
        }
        typer.echo(json.dumps(payload, default=str, ensure_ascii=False))
        return

    if verbose:
        tool_steps = [s for s in result.steps if s.kind == "tool_call"]
        if tool_steps:
            typer.echo(f"\n  Investigation steps ({len(tool_steps)}):")
            for i, step in enumerate(tool_steps, 1):
                args = step.arguments or {}
                arg_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
                typer.echo(typer.style(f"   {i}. {step.name}({arg_str})", fg=typer.colors.CYAN))
                preview = step.result.replace("\n", " ")
                if len(preview) > 200:
                    preview = preview[:200] + " ..."
                typer.echo(f"      -> {preview}")

    if result.truncated:
        typer.echo(
            typer.style(
                f"\n  [!] Step limit ({result.iterations}) reached — answer may be partial.",
                fg=typer.colors.YELLOW,
            ),
            err=True,
        )

    typer.echo("\n" + "-" * 55)
    typer.echo(result.answer.strip() or "(no answer)")
    typer.echo("-" * 55)


def _run_agent(
    cfg: Config, task: str, *, max_steps: int, verbose: bool, as_json: bool = False
) -> None:
    client = _prepare_client(cfg)
    tools = build_investigation_tools(cfg.db_path)
    agent = Agent(client, tools, system=_SYSTEM_PROMPT, max_iterations=max_steps)
    if not as_json:
        typer.echo(
            f"\n  Provider: {cfg.llm.provider}  Model: {cfg.llm.model}  (max {max_steps} steps)"
        )
    try:
        result = agent.run(task)
    except Exception as e:
        typer.echo(f"\n  Agent error: {e}", err=True)
        raise typer.Exit(1)
    _render(result, verbose=verbose, as_json=as_json)


# ---------------------------------------------------------------------------
# agent investigate <fingerprint>
# ---------------------------------------------------------------------------


@app.command("investigate")
def agent_investigate(
    fingerprint: Annotated[
        str, typer.Argument(help="Error fingerprint from 'logatory errors list'.")
    ],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    max_steps: Annotated[int, typer.Option("--max-steps", help="Max tool-use iterations.")] = 8,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show each tool call and its result.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the result as a JSON object (for CI).")
    ] = False,
) -> None:
    """Run the triage agent on a single tracked error to find its root cause."""
    cfg = Config.load(config)

    with ErrorsRepository(cfg.db_path) as repo:
        row = repo.get_error(fingerprint)
    if not row:
        typer.echo(f"Error '{fingerprint}' not found. Run 'logatory errors list' first.", err=True)
        raise typer.Exit(1)

    task = (
        f"Investigate the tracked error with fingerprint '{fingerprint}' "
        f"(type: {row['error_type']}, severity: {row['severity']}, "
        f"count: {row['count']}). Use the tools to fetch its record and recent "
        "occurrences (stack traces), look for related errors and matching findings, "
        "then explain the most likely root cause and recommend next steps."
    )
    _run_agent(cfg, task, max_steps=max_steps, verbose=verbose, as_json=json_output)


# ---------------------------------------------------------------------------
# agent ask "<question>"
# ---------------------------------------------------------------------------


@app.command("ask")
def agent_ask(
    question: Annotated[
        str, typer.Argument(help="Free-form question about your errors and findings.")
    ],
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    max_steps: Annotated[int, typer.Option("--max-steps", help="Max tool-use iterations.")] = 8,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show each tool call and its result.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the result as a JSON object (for CI).")
    ] = False,
) -> None:
    """Ask the agent a free-form question; it gathers evidence with tools as needed."""
    cfg = Config.load(config)
    _run_agent(cfg, question, max_steps=max_steps, verbose=verbose, as_json=json_output)


# ---------------------------------------------------------------------------
# agent triage
# ---------------------------------------------------------------------------

_TRIAGE_TASK = (
    "Triage the current state of the system. Begin with get_summary to orient "
    "yourself, then use list_errors (try both sort=count and sort=severity), "
    "top_finding_rules, list_regressions and error_trend to find what matters most. "
    "When an error or rule looks important, drill in with get_occurrences or "
    "get_findings_by_rule for concrete evidence. Finish with a prioritized report: "
    "for each top issue give its severity, why it matters, the supporting evidence, "
    "and a recommended next action. If there is little or no data, say so plainly."
)


@app.command("triage")
def agent_triage(
    config: Annotated[Optional[Path], typer.Option("--config", "-c")] = None,
    max_steps: Annotated[int, typer.Option("--max-steps", help="Max tool-use iterations.")] = 10,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show each tool call and its result.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the result as a JSON object (for CI).")
    ] = False,
) -> None:
    """Auto-triage the whole dataset: the agent surveys errors and findings and
    produces a prioritized report — no fingerprint needed."""
    cfg = Config.load(config)
    _run_agent(cfg, _TRIAGE_TASK, max_steps=max_steps, verbose=verbose, as_json=json_output)
