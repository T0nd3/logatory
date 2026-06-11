"""Tests for the S3 / object-storage source adapter."""

from __future__ import annotations

import gzip
import json

import pytest

from logatory.adapters.s3 import S3Adapter, _parse_ts

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _listing(*objects: tuple[str, str]) -> str:
    """Render a list-objects-v2 JSON response from (key, last_modified) pairs."""
    return json.dumps(
        {"Contents": [{"Key": key, "LastModified": ts, "Size": 100} for key, ts in objects]}
    )


class _Runner:
    """Injectable aws stand-in: serves a listing, then canned object bodies."""

    def __init__(self, listing: str, bodies: dict[str, str]) -> None:
        self._listing = listing
        self._bodies = bodies
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> str:
        self.calls.append(args)
        if "list-objects-v2" in args:
            return self._listing
        # `aws s3 cp s3://bucket/key -` — the URI is the second-to-last arg.
        uri = args[-2]
        key = uri.split("/", 3)[3]
        return self._bodies.get(key, "")


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


class TestParseTs:
    def test_iso_with_offset(self):
        dt = _parse_ts("2026-06-11T10:00:00+00:00")
        assert dt is not None and dt.year == 2026

    def test_iso_with_zulu(self):
        dt = _parse_ts("2026-06-11T10:00:00Z")
        assert dt is not None and dt.tzinfo is not None

    def test_naive_gets_utc(self):
        dt = _parse_ts("2026-06-11T10:00:00")
        assert dt is not None and dt.tzinfo is not None

    def test_invalid_returns_none(self):
        assert _parse_ts("not-a-date") is None
        assert _parse_ts(None) is None
        assert _parse_ts("") is None


# ---------------------------------------------------------------------------
# Construction / command building
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_bucket_required(self):
        with pytest.raises(ValueError, match="bucket"):
            S3Adapter(bucket="")

    def test_list_args_include_prefix_and_globals(self):
        adapter = S3Adapter(
            bucket="logs", prefix="app/", endpoint_url="http://minio:9000", region="eu-1"
        )
        args = adapter._list_args()
        assert "list-objects-v2" in args
        assert "--bucket" in args and "logs" in args
        assert "--prefix" in args and "app/" in args
        assert "--endpoint-url" in args and "http://minio:9000" in args
        assert "--region" in args and "eu-1" in args

    def test_cp_args_build_uri(self):
        adapter = S3Adapter(bucket="logs", profile="prod")
        args = adapter._cp_args("a/b.log")
        assert args[:4] == ["aws", "s3", "cp", "s3://logs/a/b.log"]
        assert "--profile" in args and "prod" in args


# ---------------------------------------------------------------------------
# Object listing
# ---------------------------------------------------------------------------


class TestListObjects:
    def test_sorted_oldest_first(self):
        runner = _Runner(
            _listing(
                ("new.log", "2026-06-11T12:00:00Z"),
                ("old.log", "2026-06-11T08:00:00Z"),
            ),
            {},
        )
        adapter = S3Adapter(bucket="logs", runner=runner)
        keys = [k for k, _ in adapter._list_objects()]
        assert keys == ["old.log", "new.log"]

    def test_skips_directory_placeholders(self):
        runner = _Runner(
            _listing(("app/", "2026-06-11T08:00:00Z"), ("app/x.log", "2026-06-11T09:00:00Z")),
            {},
        )
        adapter = S3Adapter(bucket="logs", runner=runner)
        keys = [k for k, _ in adapter._list_objects()]
        assert keys == ["app/x.log"]

    def test_empty_listing(self):
        runner = _Runner(json.dumps({"KeyCount": 0}), {})
        adapter = S3Adapter(bucket="logs", runner=runner)
        assert adapter._list_objects() == []

    def test_invalid_json_returns_empty(self):
        runner = _Runner("not json", {})
        adapter = S3Adapter(bucket="logs", runner=runner)
        assert adapter._list_objects() == []


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------


class TestEvents:
    async def test_reads_objects_and_tags_source(self):
        runner = _Runner(
            _listing(("a.log", "2026-06-11T08:00:00Z")),
            {"a.log": "hello one\nhello two\n"},
        )
        adapter = S3Adapter(bucket="logs", runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["hello one", "hello two"]
        assert all(e.source == "s3://logs/a.log" for e in events)
        assert events[0].parsed_fields["bucket"] == "logs"
        assert events[0].parsed_fields["key"] == "a.log"
        assert "last_modified" in events[0].parsed_fields

    async def test_parses_json_lines_object(self):
        body = "\n".join(json.dumps({"level": "error", "message": m}) for m in ("boom", "kaboom"))
        runner = _Runner(_listing(("j.log", "2026-06-11T08:00:00Z")), {"j.log": body})
        adapter = S3Adapter(bucket="logs", runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["boom", "kaboom"]
        assert events[0].severity.value == "error"

    async def test_multiple_objects_oldest_first(self):
        runner = _Runner(
            _listing(
                ("b.log", "2026-06-11T10:00:00Z"),
                ("a.log", "2026-06-11T08:00:00Z"),
            ),
            {"a.log": "from a\n", "b.log": "from b\n"},
        )
        adapter = S3Adapter(bucket="logs", runner=runner)
        events = [e async for e in adapter.events()]
        assert [e.message for e in events] == ["from a", "from b"]

    async def test_empty_object_skipped(self):
        runner = _Runner(
            _listing(("empty.log", "2026-06-11T08:00:00Z")),
            {"empty.log": "   \n\n"},
        )
        adapter = S3Adapter(bucket="logs", runner=runner)
        assert [e async for e in adapter.events()] == []


# ---------------------------------------------------------------------------
# Gzip handling (real subprocess decode path)
# ---------------------------------------------------------------------------


class TestGzip:
    def test_decompresses_gz_objects(self, monkeypatch):
        payload = gzip.compress(b"line one\nline two\n")

        class _Result:
            returncode = 0
            stdout = payload
            stderr = b""

        monkeypatch.setattr("logatory.adapters.s3.subprocess.run", lambda *a, **k: _Result())
        adapter = S3Adapter(bucket="logs")  # no runner -> real subprocess path
        text = adapter._read_object("archive.log.gz")
        assert text == "line one\nline two\n"

    def test_non_gzip_with_gz_suffix_falls_back(self, monkeypatch):
        class _Result:
            returncode = 0
            stdout = b"plain text\n"
            stderr = b""

        monkeypatch.setattr("logatory.adapters.s3.subprocess.run", lambda *a, **k: _Result())
        adapter = S3Adapter(bucket="logs")
        assert adapter._read_object("mislabeled.gz") == "plain text\n"


# ---------------------------------------------------------------------------
# Poll / dedup
# ---------------------------------------------------------------------------


class TestPoll:
    async def test_dedup_by_key(self):
        # Round 1 lists a.log; round 2 re-lists a.log and adds b.log.
        listings = [
            _listing(("a.log", "2026-06-11T08:00:00Z")),
            _listing(
                ("a.log", "2026-06-11T08:00:00Z"),
                ("b.log", "2026-06-11T09:00:00Z"),
            ),
        ]

        class _PollRunner:
            def __init__(self):
                self.round = 0
                self.bodies = {"a.log": "a one\n", "b.log": "b one\n"}

            def __call__(self, args):
                if "list-objects-v2" in args:
                    out = listings[min(self.round, len(listings) - 1)]
                    self.round += 1
                    return out
                key = args[-2].split("/", 3)[3]
                return self.bodies.get(key, "")

        adapter = S3Adapter(bucket="logs", runner=_PollRunner())
        collected: list[str] = []
        async for event in adapter.poll(interval=0):
            collected.append(event.message)
            if len(collected) >= 2:
                break

        # a.log delivered once even though it appears in both listings.
        assert collected == ["a one", "b one"]
