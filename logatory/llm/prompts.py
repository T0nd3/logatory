"""Prompt templates for the LLM layer.

All functions return a plain string ready to be sent to the LLM.
No LLM calls happen here — this is pure text manipulation.
"""

from __future__ import annotations

import json

from ..models import Finding

# Maximum characters included per context item (keeps prompts within token budget)
_MAX_ITEM_CHARS = 400
_MAX_CONTEXT_ITEMS = 8
# A full stack trace is the richest signal for explaining an error, so give it
# generous room — the prompt still stays well within the model context window.
_MAX_STACK_CHARS = 4000


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def explain_finding_prompt(finding: Finding, occurrence_samples: list[str] | None = None) -> str:
    """Prompt asking the LLM to explain a rule-based or anomaly finding."""
    ts = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    sev = finding.severity.value.upper()

    lines = [
        "You are a log analysis expert. Explain the following finding concisely.",
        "",
        "FINDING:",
        f"  Rule     : {finding.rule_id}",
        f"  Severity : {sev}",
        f"  Time     : {ts}",
        f"  Source   : {finding.source}",
        f"  Message  : {finding.message}",
    ]

    if finding.details:
        details_str = json.dumps(finding.details, indent=2)[:600]
        lines += ["  Details  :", f"{details_str}"]

    if occurrence_samples:
        lines += ["", "SAMPLE LOG LINES:"]
        for sample in occurrence_samples[:5]:
            lines.append(f"  > {sample[:200]}")

    lines += [
        "",
        "Answer these three questions in 3–5 sentences total:",
        "1. What happened?",
        "2. What is the likely cause?",
        "3. What should be done next?",
        "",
        "Be specific and actionable.",
    ]
    return "\n".join(lines)


def explain_error_prompt(error_row: dict, occurrences: list[dict] | None = None) -> str:
    """Prompt for explaining a persisted error (from the errors table)."""
    lines = [
        "You are a log analysis expert. Explain the following recurring error.",
        "",
        "ERROR PATTERN:",
        f"  Type       : {error_row.get('error_type', '?')}",
        f"  Severity   : {error_row.get('severity', '?').upper()}",
        f"  Count      : {error_row.get('count', '?'):,}",
        f"  First seen : {error_row.get('first_seen', '?')[:19]}",
        f"  Last seen  : {error_row.get('last_seen', '?')[:19]}",
        f"  Normalized : {error_row.get('normalized_msg', '?')[:300]}",
    ]

    occurrences = occurrences or []

    # Include the full stack trace from the most recent occurrence that has one.
    # The trace (function names, files, line numbers, call chain) is the richest
    # signal the LLM gets without access to the source code.
    trace_occ = next((o for o in occurrences if o.get("stack_trace")), None)
    if trace_occ:
        lang = trace_occ.get("stack_lang") or "unknown"
        lines += [
            "",
            f"STACK TRACE ({lang}):",
            trace_occ["stack_trace"][:_MAX_STACK_CHARS],
        ]

    if occurrences:
        lines += ["", "RECENT SAMPLES:"]
        for occ in occurrences[:4]:
            sample = occ.get("sample", "")[:200]
            ts = occ.get("timestamp", "")[:19]
            lines.append(f"  [{ts}] {sample}")

    lines += [
        "",
        "Answer concisely (3–5 sentences):",
        "1. What does this error mean?",
        "2. What typically causes it?",
        "3. How to fix or investigate it?",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------


def summarize_prompt(
    error_rows: list[dict],
    since: str,
) -> str:
    """Prompt for a natural-language summary of the most frequent recent errors."""
    if not error_rows:
        return (
            "There are no tracked errors in the database. "
            "Run 'logatory scan --track-errors' first."
        )

    lines = [
        f"You are a log analysis expert. Summarize the error situation for the last {since}.",
        "",
        f"TOP ERRORS (last {since}, sorted by frequency):",
    ]
    lines.extend(
        f"  [{row.get('count', 0):>5}x] [{row.get('severity', '?').upper():<8}] "
        f"{row.get('error_type', '?')} — {row.get('normalized_msg', '')[:_MAX_ITEM_CHARS]}"
        for row in error_rows[:_MAX_CONTEXT_ITEMS]
    )

    lines += [
        "",
        "Write a concise summary (max 150 words) covering:",
        "- The most critical issues and their impact",
        "- Any obvious patterns or correlations",
        "- What deserves immediate attention",
        "",
        "Use bullet points. Be direct.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ask (RAG)
# ---------------------------------------------------------------------------


def ask_prompt(question: str, context_chunks: list[str]) -> str:
    """RAG prompt: answer a question based on retrieved findings/error context."""
    if context_chunks:
        ctx = "\n\n---\n\n".join(
            chunk[:_MAX_ITEM_CHARS] for chunk in context_chunks[:_MAX_CONTEXT_ITEMS]
        )
    else:
        ctx = "(No relevant context found in the database.)"

    return "\n".join(
        [
            "You are a log analysis assistant.",
            "Answer the question based on the context below (findings and errors from the local database).",
            "If the context is insufficient, say so clearly — do not invent details.",
            "",
            "CONTEXT:",
            ctx,
            "",
            f"QUESTION: {question}",
            "",
            "Answer concisely and accurately.",
        ]
    )


# ---------------------------------------------------------------------------
# classify (for unstructured logs)
# ---------------------------------------------------------------------------


def classify_events_prompt(log_lines: list[str]) -> str:
    """Ask the LLM to classify raw log lines by severity."""
    numbered = "\n".join(f"  {i + 1:>3}. {line[:200]}" for i, line in enumerate(log_lines[:30]))
    return (
        "You are a log analysis expert.\n"
        "Classify each log line by severity. Use: DEBUG, INFO, WARNING, ERROR, CRITICAL.\n"
        "\n"
        "LOG LINES:\n"
        f"{numbered}\n"
        "\n"
        "For each line respond with:\n"
        "  LINE <N>: [SEVERITY] <one-sentence description>\n"
        "\n"
        "Focus on errors, warnings, and security-relevant events. Skip purely informational lines."
    )
