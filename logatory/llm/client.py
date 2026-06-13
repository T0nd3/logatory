"""Ollama HTTP client — pure stdlib, no extra dependencies.

Communicates with a locally running Ollama instance via its REST API.
All calls are synchronous; streaming generation yields tokens one at a time.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any

from .base import AbstractLLMClient
from .tools import messages_to_ollama, parse_ollama_message

if TYPE_CHECKING:
    from .tools import AssistantTurn, Msg, ToolSpec


class OllamaError(RuntimeError):
    """Raised when Ollama returns an error or is unreachable."""


class OllamaClient(AbstractLLMClient):
    """Thin wrapper around the Ollama REST API."""

    is_cloud = False
    provider_name = "ollama"
    supports_tools = True

    def __init__(
        self,
        endpoint: str = "http://localhost:11434",
        model: str = "gemma3:4b",
        temperature: float = 0.1,
        max_context_tokens: int = 8000,
        embed_model: str = "nomic-embed-text",
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._temperature = temperature
        self._max_context_tokens = max_context_tokens
        self._embed_model = embed_model

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def is_available(self, timeout: int = 3) -> bool:
        """Return True if Ollama is running and reachable."""
        try:
            urllib.request.urlopen(f"{self._endpoint}/api/tags", timeout=timeout)
            return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return names of locally available models."""
        try:
            with urllib.request.urlopen(f"{self._endpoint}/api/tags", timeout=5) as resp:
                data = json.loads(resp.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Text generation
    # ------------------------------------------------------------------

    def generate(self, prompt: str, stream: bool = True) -> Iterator[str]:
        """Generate text, yielding tokens as they arrive.

        Set stream=False to get the full response in one chunk (still yields
        it as a single string for a uniform interface).
        """
        payload: dict[str, Any] = {
            "model": self._model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": self._temperature,
                "num_ctx": self._max_context_tokens,
            },
        }
        req = urllib.request.Request(
            f"{self._endpoint}/api/generate",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                if stream:
                    for raw in resp:
                        line = raw.strip()
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        token = chunk.get("response", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                else:
                    data = json.loads(resp.read())
                    yield data.get("response", "")
        except urllib.error.URLError as e:
            raise OllamaError(f"Cannot reach Ollama at {self._endpoint}: {e}") from e

    def generate_full(self, prompt: str) -> str:
        """Convenience method — return the complete response as a string."""
        return "".join(self.generate(prompt, stream=False))

    # ------------------------------------------------------------------
    # Tool use (agent mode) — native Ollama /api/chat
    # ------------------------------------------------------------------

    def chat_with_tools(
        self,
        messages: list[Msg],
        tools: list[ToolSpec],
        system: str = "",
    ) -> AssistantTurn:
        """Run one tool-enabled turn via Ollama's native ``/api/chat`` endpoint.

        Requires a tool-capable model (e.g. ``llama3.1``, ``qwen2.5``,
        ``mistral-nemo``). The OpenAI-style tool schema is reused verbatim, since
        Ollama accepts the same ``{"type": "function", ...}`` shape.
        """
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": messages_to_ollama(messages, system or None),
            "stream": False,
            "options": {
                "temperature": self._temperature,
                "num_ctx": self._max_context_tokens,
            },
        }
        if tools:
            payload["tools"] = [t.to_openai() for t in tools]
        req = urllib.request.Request(
            f"{self._endpoint}/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as e:
            raise OllamaError(f"Cannot reach Ollama at {self._endpoint}: {e}") from e
        return parse_ollama_message(data.get("message", {}))

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    def embed(self, text: str) -> list[float]:
        """Return an embedding vector for the given text.

        Tries the newer /api/embed endpoint first; falls back to the older
        /api/embeddings if the server does not support it.
        """
        for path, key, field in (
            ("/api/embed", "input", "embeddings"),
            ("/api/embeddings", "prompt", "embedding"),
        ):
            payload = {"model": self._embed_model, key: text}
            req = urllib.request.Request(
                f"{self._endpoint}{path}",
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    result = json.loads(resp.read())
                    if field == "embeddings":
                        vecs = result.get("embeddings", [])
                        return vecs[0] if vecs else []
                    return result.get("embedding", [])
            except urllib.error.HTTPError:
                continue
            except urllib.error.URLError as e:
                raise OllamaError(f"Cannot reach Ollama at {self._endpoint}: {e}") from e
        return []
