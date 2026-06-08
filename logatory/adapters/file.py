from __future__ import annotations

import gzip
from collections.abc import AsyncIterator
from pathlib import Path

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter


class FileAdapter(SourceAdapter):
    """Reads log events from a single file (plain or gzip-compressed)."""

    def __init__(self, path: Path) -> None:
        self.path = path

    async def events(self) -> AsyncIterator[Event]:
        lines = self._read_lines()
        sample = []
        buf = []
        for line in lines:
            buf.append(line)
            if len(sample) < 5 and line.strip():
                sample.append(line)
            if len(buf) >= 512:
                break

        fmt = FormatDetector().detect(sample)
        parser = get_parser(fmt, source=str(self.path))

        for line in buf:
            event = parser.parse(line)
            if event is not None:
                yield event

        for line in self._read_lines(skip=len(buf)):
            event = parser.parse(line)
            if event is not None:
                yield event

    def _read_lines(self, skip: int = 0):
        if self.path.suffix.lower() == ".xlsx":
            yield from self._read_xlsx_lines(skip=skip)
            return
        open_fn = gzip.open if self.path.suffix == ".gz" else open
        with open_fn(self.path, "rt", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i < skip:
                    continue
                yield line

    def _read_xlsx_lines(self, skip: int = 0):
        try:
            from openpyxl import load_workbook
        except ImportError as exc:
            raise RuntimeError("openpyxl not installed. Run: pip install logatory[xlsx]") from exc

        wb = load_workbook(self.path, read_only=True, data_only=True)
        try:
            i = 0
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    if i >= skip:
                        cells = ["" if c is None else str(c) for c in row]
                        yield "\t".join(cells)
                    i += 1
        finally:
            wb.close()
