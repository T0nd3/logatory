"""Shared polling machinery for HTTP-backed source adapters.

Graylog, Loki and OpenSearch all pull batches over HTTP and, in realtime
mode, must keep advancing a cursor while skipping the entries that overlap
the previous batch's boundary. That bookkeeping is identical across all
three and easy to get subtly wrong, so it lives here once.

Subclasses describe *what* to fetch and how to interpret a batch through a
handful of hooks; this base owns the *when* — the cursor and deduplication
logic that keeps realtime polling from dropping or repeating events.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Hashable
from typing import Any

from ..models import Event
from .base import SourceAdapter


class HttpPollingAdapter(SourceAdapter):
    """Base for adapters that fetch event batches over HTTP and poll for more.

    A subclass implements the hooks below; ``events()`` (one-shot) and
    ``poll()`` (realtime) are provided and shared.
    """

    # -- hooks (override in subclasses) ------------------------------------

    def _initial_cursor(self) -> Any:
        """Cursor value for the first fetch, in both batch and realtime mode."""
        return None

    def _fetch_batch(self, cursor: Any) -> list[Any]:
        """Fetch one batch of raw items for ``cursor``. Must be overridden."""
        raise NotImplementedError

    def _prepare_batch(self, items: list[Any]) -> None:
        """Hook run once per non-empty batch before its items are mapped.

        Default is a no-op; Loki uses it to lazily build its parser from a
        sample of the first batch.
        """

    def _make_event(self, item: Any) -> Event | None:
        """Map one raw item to an Event, or return None to skip it."""
        raise NotImplementedError

    def _dedup_key(self, item: Any) -> Hashable | None:
        """Stable identity used to skip entries seen in the previous batch.

        Return None when an item has no usable identity; such items are
        always delivered and never deduplicated.
        """
        return None

    def _advance_cursor(self, cursor: Any, item: Any, event: Event | None) -> Any:
        """Return the cursor to use after processing ``item``.

        Called for every non-skipped item, even when ``_make_event`` returned
        None, so cursors derived from the raw item (rather than the parsed
        event) keep advancing past unparseable lines. Default: unchanged.
        """
        return cursor

    # -- shared behaviour --------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield every event in a single batch (one-shot mode)."""
        items = self._fetch_batch(self._initial_cursor())
        if items:
            self._prepare_batch(items)
        for item in items:
            event = self._make_event(item)
            if event is not None:
                yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll forever, yielding only entries not seen in the prior batch.

        Each round fetches from the current cursor, skips items whose dedup
        key appeared in the previous batch, delivers the rest, and advances
        the cursor. Runs until the caller stops iterating.
        """
        cursor = self._initial_cursor()
        seen: set[Hashable] = set()

        while True:
            items = self._fetch_batch(cursor)
            if items:
                self._prepare_batch(items)

            batch_keys: set[Hashable] = set()
            for item in items:
                key = self._dedup_key(item)
                if key is not None:
                    batch_keys.add(key)
                    if key in seen:
                        continue
                event = self._make_event(item)
                cursor = self._advance_cursor(cursor, item, event)
                if event is not None:
                    yield event

            if batch_keys:
                seen = batch_keys

            await asyncio.sleep(interval)
