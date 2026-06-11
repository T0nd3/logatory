"""S3 / object-storage source adapter — reads log objects via the `aws` CLI.

Logs shipped to object storage (S3, or any S3-compatible store like MinIO,
Cloudflare R2, Backblaze B2, Wasabi, …) can be analyzed straight from the
bucket — no download-and-unzip dance. This adapter shells out to the system
`aws` CLI (no boto3 dependency), so your AWS profile, SSO session, instance
role and `~/.aws/config` all apply unchanged. Read-only — it only ever runs
`list-objects-v2` and `s3 cp`.

Objects are discovered with `aws s3api list-objects-v2` (honouring a key
prefix), then each object's body is streamed with `aws s3 cp s3://… -`.
Gzip-compressed objects (``*.gz``) are decompressed transparently, and the
inner content is parsed exactly like any other source (JSON, logfmt,
plaintext, …). Every event is tagged with its bucket and key.

Point `--endpoint-url` at a non-AWS host to read from any S3-compatible
service.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from ..models import Event
from ..parsers.detector import FormatDetector
from ..parsers.registry import get_parser
from .base import SourceAdapter


def _parse_ts(value: str | None) -> datetime | None:
    """Parse an ISO 8601 timestamp (as returned by ``list-objects-v2``)."""
    if not value or not isinstance(value, str):
        return None
    token = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(token)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class S3Adapter(SourceAdapter):
    """Reads log events from object-storage objects via the system `aws` CLI.

    Objects are selected by bucket and an optional key prefix. Each object's
    body is read and parsed individually so events can be tagged with the
    exact key they came from. Works against AWS S3 or any S3-compatible store
    via ``endpoint_url``.
    """

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str | None = None,
        endpoint_url: str | None = None,
        region: str | None = None,
        profile: str | None = None,
        max_objects: int = 50,
        runner=None,
    ) -> None:
        if not bucket:
            raise ValueError("S3Adapter needs a 'bucket'.")
        self._bucket = bucket
        self._prefix = prefix
        self._endpoint_url = endpoint_url
        self._region = region
        self._profile = profile
        self._max_objects = max_objects
        self._runner = runner  # injectable for tests: (list[str]) -> str

    # -- aws command construction ------------------------------------------

    def _global_args(self) -> list[str]:
        args: list[str] = []
        if self._endpoint_url:
            args += ["--endpoint-url", self._endpoint_url]
        if self._region:
            args += ["--region", self._region]
        if self._profile:
            args += ["--profile", self._profile]
        return args

    def _list_args(self) -> list[str]:
        args = [
            "aws",
            "s3api",
            "list-objects-v2",
            "--bucket",
            self._bucket,
            "--output",
            "json",
            "--max-keys",
            str(self._max_objects),
        ]
        if self._prefix:
            args += ["--prefix", self._prefix]
        return [*args, *self._global_args()]

    def _cp_args(self, key: str) -> list[str]:
        return ["aws", "s3", "cp", f"s3://{self._bucket}/{key}", "-", *self._global_args()]

    # -- runner (real subprocess; overridable for tests) -------------------

    def _run(self, args: list[str]) -> str:
        if self._runner is not None:
            return self._runner(args)
        try:
            result = subprocess.run(args, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            raise RuntimeError("aws CLI not found — install the AWS CLI to use the s3 adapter.")
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit code {result.returncode}"
            raise RuntimeError(f"aws failed: {detail}")
        return result.stdout

    def _read_object(self, key: str) -> str:
        """Stream one object's body to text, decompressing ``*.gz`` transparently."""
        if self._runner is not None:
            # Tests inject already-decoded text; gzip handling is exercised by
            # the real subprocess path below.
            return self._runner(self._cp_args(key))
        try:
            result = subprocess.run(self._cp_args(key), capture_output=True, check=False)
        except FileNotFoundError:
            raise RuntimeError("aws CLI not found — install the AWS CLI to use the s3 adapter.")
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip() or "read failed"
            raise RuntimeError(f"aws failed reading {key}: {detail}")
        data = result.stdout
        if key.lower().endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError):
                pass  # not actually gzip — fall back to raw bytes
        return data.decode("utf-8", errors="replace")

    # -- object listing ----------------------------------------------------

    def _list_objects(self) -> list[tuple[str, datetime | None]]:
        """Return (key, last_modified) for each object, oldest-first.

        Zero-byte "directory" placeholders (keys ending in ``/``) are skipped.
        """
        output = self._run(self._list_args())
        try:
            data = json.loads(output) if output.strip() else {}
        except json.JSONDecodeError:
            return []

        contents = data.get("Contents") if isinstance(data, dict) else None
        if not isinstance(contents, list):
            return []

        objects: list[tuple[str, datetime | None]] = []
        for item in contents:
            if not isinstance(item, dict):
                continue
            key = item.get("Key")
            if not key or key.endswith("/"):
                continue
            objects.append((key, _parse_ts(item.get("LastModified"))))

        # Oldest first so events arrive in roughly chronological order. Objects
        # without a parseable timestamp sort to the end of the batch.
        objects.sort(key=lambda kv: kv[1] or datetime.max.replace(tzinfo=UTC))
        return objects

    # -- event construction ------------------------------------------------

    def _events_from_object(self, key: str, last_modified: datetime | None) -> list[Event]:
        text = self._read_object(key)
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return []
        name = f"s3://{self._bucket}/{key}"
        parser = get_parser(FormatDetector().detect(lines[:5]), source=name)
        events: list[Event] = []
        for line in lines:
            event = parser.parse(line)
            if event is None:
                continue
            event.source = name
            event.parsed_fields["bucket"] = self._bucket
            event.parsed_fields["key"] = key
            if last_modified is not None:
                event.parsed_fields["last_modified"] = last_modified.isoformat()
            events.append(event)
        return events

    # -- public API --------------------------------------------------------

    async def events(self) -> AsyncIterator[Event]:
        """Yield every event from all matching objects once (batch mode)."""
        for key, last_modified in self._list_objects():
            for event in self._events_from_object(key, last_modified):
                yield event

    async def poll(self, interval: float) -> AsyncIterator[Event]:
        """Poll the bucket forever, yielding events from newly-arrived objects.

        Objects are immutable in S3 — new logs appear as new keys — so each
        object is read exactly once, tracked by key. Objects present when the
        poll began are read on the first round. Runs until the caller stops
        iterating.
        """
        seen: set[str] = set()
        while True:
            for key, last_modified in self._list_objects():
                if key in seen:
                    continue
                seen.add(key)
                for event in self._events_from_object(key, last_modified):
                    yield event
            await asyncio.sleep(interval)
