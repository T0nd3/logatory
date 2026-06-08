from pathlib import Path

import pytest

from logatory.adapters.file import FileAdapter
from logatory.models import Severity

DATA_DIR = Path(__file__).parent / "data"


async def collect(adapter) -> list:
    return [e async for e in adapter.events()]


class TestFileAdapter:
    async def test_nginx_log_parses_all_lines(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        assert len(events) == 7

    async def test_nginx_event_has_status_field(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        assert all("status" in e.parsed_fields for e in events)

    async def test_nginx_500_is_error(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        errors = [e for e in events if e.severity == Severity.ERROR]
        assert len(errors) == 1
        assert errors[0].parsed_fields["status"] == 500

    async def test_auth_log_parses(self, auth_log):
        events = await collect(FileAdapter(auth_log))
        assert len(events) == 7

    async def test_syslog_parses(self, syslog_log):
        events = await collect(FileAdapter(syslog_log))
        assert len(events) == 6

    async def test_json_log_parses(self, json_log):
        events = await collect(FileAdapter(json_log))
        assert len(events) == 6
        error_events = [e for e in events if e.severity == Severity.ERROR]
        assert len(error_events) == 1

    async def test_source_is_file_path(self, nginx_log):
        events = await collect(FileAdapter(nginx_log))
        assert all(str(nginx_log) in e.source for e in events)


@pytest.fixture
def xlsx_log(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    path = tmp_path / "logs.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["server started"])
    ws.append(["connection failed", "ERROR"])
    ws.append([None, None])  # blank row, should be skipped by the parser
    ws.append(["request handled", 200])
    wb.save(path)
    return path


class TestXlsxFileAdapter:
    async def test_xlsx_rows_become_events(self, xlsx_log):
        events = await collect(FileAdapter(xlsx_log))
        assert len(events) == 3

    async def test_xlsx_no_replacement_chars(self, xlsx_log):
        events = await collect(FileAdapter(xlsx_log))
        assert all("�" not in e.raw for e in events)

    async def test_xlsx_cell_content_readable(self, xlsx_log):
        events = await collect(FileAdapter(xlsx_log))
        assert any("server started" in e.message for e in events)

    async def test_xlsx_severity_inferred_from_cells(self, xlsx_log):
        events = await collect(FileAdapter(xlsx_log))
        errors = [e for e in events if e.severity == Severity.ERROR]
        assert len(errors) == 1
        assert "connection failed" in errors[0].message
