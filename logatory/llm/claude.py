"""Claude (Anthropic) LLM client.

Requires: pip install logatory[claude]  (installs anthropic SDK)
API key:  set ANTHROPIC_API_KEY env var  or  llm.api_key in config.yaml
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from typing import TYPE_CHECKING

from .base import AbstractLLMClient
from .tools import messages_to_anthropic, parse_anthropic_response

if TYPE_CHECKING:
    from .tools import AssistantTurn, Msg, ToolSpec

_SDK_AVAILABLE = importlib.util.find_spec("anthropic") is not None

# Default model — best price/quality for log analysis tasks
_DEFAULT_MODEL = "claude-haiku-4-5"


class ClaudeClient(AbstractLLMClient):
    is_cloud = True
    provider_name = "claude"
    supports_tools = True

    def __init__(
        self,
        api_key: str | None,
        model: str = _DEFAULT_MODEL,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> None:
        self._api_key = api_key
        self._model = model or _DEFAULT_MODEL
        self._temperature = temperature
        # Claude's max output tokens; cap at 8192 for safety
        self._max_tokens = min(max_tokens, 8192)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        if not _SDK_AVAILABLE:
            return False
        if not self._api_key:
            return False
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self._api_key)
            # Lightweight call — just lists available models
            list(client.models.list(limit=1))
            return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        if not _SDK_AVAILABLE or not self._api_key:
            return []
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self._api_key)
            return [m.id for m in client.models.list()]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate(self, prompt: str, stream: bool = True) -> Iterator[str]:
        if not _SDK_AVAILABLE:
            raise RuntimeError("anthropic SDK not installed. Run: pip install logatory[claude]")
        if not self._api_key:
            raise RuntimeError(
                "No Anthropic API key found.\n"
                "Set ANTHROPIC_API_KEY or add 'api_key' under 'llm:' in your config.yaml."
            )

        import anthropic

        client = anthropic.Anthropic(api_key=self._api_key)
        messages = [{"role": "user", "content": prompt}]

        if stream:
            with client.messages.stream(
                model=self._model,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                messages=messages,
            ) as s:
                yield from s.text_stream
        else:
            msg = client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                messages=messages,
            )
            yield msg.content[0].text

    # ------------------------------------------------------------------
    # Tool use (agent mode)
    # ------------------------------------------------------------------

    def chat_with_tools(
        self,
        messages: list[Msg],
        tools: list[ToolSpec],
        system: str = "",
    ) -> AssistantTurn:
        if not _SDK_AVAILABLE:
            raise RuntimeError("anthropic SDK not installed. Run: pip install logatory[claude]")
        if not self._api_key:
            raise RuntimeError(
                "No Anthropic API key found.\n"
                "Set ANTHROPIC_API_KEY or add 'api_key' under 'llm:' in your config.yaml."
            )

        import anthropic

        client = anthropic.Anthropic(api_key=self._api_key)
        kwargs: dict = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
            "messages": messages_to_anthropic(messages),
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [t.to_anthropic() for t in tools]

        msg = client.messages.create(**kwargs)
        return parse_anthropic_response(msg.content, getattr(msg, "stop_reason", "") or "")

    # Note: Claude has no public embedding API.
    # embed() inherits the default → returns [] → vector search disabled.
    # Set embed_provider: ollama in config to keep local embeddings.
