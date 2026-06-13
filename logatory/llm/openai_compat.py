"""OpenAI-compatible LLM client — pure stdlib, no extra dependency.

Works with any API that speaks the OpenAI chat-completions protocol:
  - OpenAI          (https://api.openai.com)
  - Groq            (https://api.groq.com/openai)
  - LM Studio       (http://localhost:1234)
  - Mistral         (https://api.mistral.ai)
  - Ollama          (http://localhost:11434/v1)  ← also supports this path

Set api_key to "" or None for local servers that don't need auth.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from .base import AbstractLLMClient
from .tools import messages_to_openai, parse_openai_message

if TYPE_CHECKING:
    from .tools import AssistantTurn, Msg, ToolSpec

# SSE line prefix for chat-completions streaming
_DATA_PREFIX = b"data: "
_DONE_SENTINEL = b"[DONE]"


class OpenAICompatibleClient(AbstractLLMClient):
    provider_name = "openai_compat"
    supports_tools = True

    def __init__(
        self,
        endpoint: str,
        model: str,
        api_key: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        embed_model: str = "text-embedding-3-small",
        is_cloud_provider: bool = False,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._api_key = api_key or ""
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._embed_model = embed_model
        self.is_cloud = is_cloud_provider

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["Authorization"] = f"Bearer {self._api_key}"
        return h

    def _post(self, path: str, payload: dict[str, Any], timeout: int = 120):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self._endpoint}{path}",
            data=data,
            headers=self._headers(),
            method="POST",
        )
        return urllib.request.urlopen(req, timeout=timeout)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def is_available(self, timeout: int = 3) -> bool:
        req = urllib.request.Request(
            f"{self._endpoint}/v1/models",
            headers=self._headers(),
            method="GET",
        )
        try:
            urllib.request.urlopen(req, timeout=timeout)
            return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        req = urllib.request.Request(
            f"{self._endpoint}/v1/models",
            headers=self._headers(),
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                return [m["id"] for m in data.get("data", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Generation (chat completions)
    # ------------------------------------------------------------------

    def generate(self, prompt: str, stream: bool = True) -> Iterator[str]:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
            "stream": stream,
        }
        try:
            with self._post("/v1/chat/completions", payload) as resp:
                if stream:
                    yield from self._parse_sse(resp)
                else:
                    data = json.loads(resp.read())
                    yield data["choices"][0]["message"]["content"]
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cannot reach {self._endpoint}: {e}") from e

    @staticmethod
    def _parse_sse(resp) -> Iterator[str]:
        """Parse Server-Sent Events streaming response."""
        for raw in resp:
            line = raw.strip()
            if not line.startswith(_DATA_PREFIX):
                continue
            payload = line[len(_DATA_PREFIX) :]
            if payload == _DONE_SENTINEL:
                break
            try:
                chunk = json.loads(payload)
                delta = chunk["choices"][0].get("delta", {})
                content = delta.get("content", "")
                if content:
                    yield content
            except (json.JSONDecodeError, KeyError, IndexError):
                continue

    # ------------------------------------------------------------------
    # Tool use (agent mode)
    # ------------------------------------------------------------------

    def chat_with_tools(
        self,
        messages: list[Msg],
        tools: list[ToolSpec],
        system: str = "",
    ) -> AssistantTurn:
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages_to_openai(messages, system or None),
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = [t.to_openai() for t in tools]
            payload["tool_choice"] = "auto"
        try:
            with self._post("/v1/chat/completions", payload) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cannot reach {self._endpoint}: {e}") from e
        message = data["choices"][0]["message"]
        return parse_openai_message(message)

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    def embed(self, text: str) -> list[float]:
        payload = {"model": self._embed_model, "input": text}
        try:
            with self._post("/v1/embeddings", payload, timeout=30) as resp:
                data = json.loads(resp.read())
                items = data.get("data", [])
                return items[0].get("embedding", []) if items else []
        except Exception:
            return []
