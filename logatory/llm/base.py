"""Abstract base class for all LLM provider clients.

Every concrete client (Ollama, Claude, OpenAI-compatible, …) must subclass
AbstractLLMClient and implement the two abstract methods.  Optional capabilities
(embeddings, model listing) have no-op defaults so providers that don't support
them degrade gracefully rather than crashing.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .tools import AssistantTurn, Msg, ToolSpec


class AbstractLLMClient(ABC):
    # Subclasses override these class-level attributes
    is_cloud: bool = False  # True → data leaves the machine
    provider_name: str = "unknown"
    supports_tools: bool = False  # True → chat_with_tools is implemented

    # ------------------------------------------------------------------
    # Required
    # ------------------------------------------------------------------

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider is reachable and ready."""

    @abstractmethod
    def generate(self, prompt: str, stream: bool = True) -> Iterator[str]:
        """Yield response tokens.

        When stream=False, yield the full response as a single token.
        Raise OllamaError / a RuntimeError on connectivity or auth failure.
        """

    # ------------------------------------------------------------------
    # Concrete (with sensible defaults)
    # ------------------------------------------------------------------

    def generate_full(self, prompt: str) -> str:
        """Convenience: collect the full response as a single string."""
        return "".join(self.generate(prompt, stream=False))

    def embed(self, text: str) -> list[float]:
        """Return an embedding vector for *text*.

        Providers that don't support embeddings return an empty list.
        The retrieval layer treats an empty list as "no vector search".
        """
        return []

    def list_models(self) -> list[str]:
        """Return names of locally/remotely available models, or []."""
        return []

    def chat_with_tools(
        self,
        messages: list[Msg],
        tools: list[ToolSpec],
        system: str = "",
    ) -> AssistantTurn:
        """Run one tool-enabled turn and return the model's response.

        Providers that support function/tool calling override this and set
        ``supports_tools = True``.  The default raises so the agent layer can
        fail fast with a helpful message.
        """
        raise NotImplementedError(
            f"Provider '{self.provider_name}' does not support tool use (agent mode)."
        )
