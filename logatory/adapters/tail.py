"""Async adapter that streams Events from a growing log file (like `tail -f`).

Behaviour
---------
- Seeks to the end of the file on first open (only *new* lines).
  Use ``from_start=True`` to read from the beginning.
- Detects truncation/rotation: if the file shrinks below the last known
  position the handle is reset to the beginning.
- Handles temporary disappearance (rename + recreate): closes the handle
  and waits until the path reappears.
- Detects log format from an initial sample so the correct parser is used.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

from ..models import Event
from ..parsers.detector import FormatDetector, LogFormat
from ..parsers.registry import get_parser
from .base import SourceAdapter

_SAMPLE_LINES = 10  # lines used for format detection
_DEFAULT_POLL = 0.2  # seconds between polls when no new data arrives


class TailAdapter(SourceAdapter):
    """Streams Events from a growing log file indefinitely."""

    def __init__(
        self,
        path: Path,
        from_start: bool = False,
        poll_interval: float = _DEFAULT_POLL,
    ) -> None:
        self.path = path
        self.from_start = from_start
        self.poll_interval = poll_interval

    # ------------------------------------------------------------------
    # SourceAdapter interface
    # ------------------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:  # type: ignore[override]
        fmt = self._detect_format()
        parser = get_parser(fmt, source=str(self.path))

        f = None
        last_pos: int = 0
        first_open = True

        try:
            while True:
                # ── open / reopen ──────────────────────────────────────
                if f is None:
                    try:
                        f = self.path.open(encoding="utf-8", errors="replace")
                        if first_open and not self.from_start:
                            f.seek(0, 2)  # seek to end on very first open
                        first_open = False
                        last_pos = f.tell()
                    except FileNotFoundError:
                        await asyncio.sleep(self.poll_interval)
                        continue

                # ── rotation / truncation check ────────────────────────
                try:
                    current_size = self.path.stat().st_size
                except FileNotFoundError:
                    # file temporarily gone — close and wait
                    f.close()
                    f = None
                    await asyncio.sleep(self.poll_interval)
                    continue

                if current_size < last_pos:
                    # file shrank → truncated (log rotation without rename)
                    f.seek(0)
                    last_pos = 0

                # ── read one line ──────────────────────────────────────
                line = f.readline()
                if line:
                    last_pos = f.tell()
                    event = parser.parse(line)
                    if event is not None:
                        yield event
                else:
                    await asyncio.sleep(self.poll_interval)

        finally:
            if f is not None:
                f.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _detect_format(self) -> LogFormat | str:
        """Read the first few lines to detect the log format."""
        sample: list[str] = []
        try:
            with self.path.open(encoding="utf-8", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= _SAMPLE_LINES:
                        break
                    if line.strip():
                        sample.append(line)
        except (FileNotFoundError, PermissionError):
            pass
        return FormatDetector().detect(sample, self.path)
