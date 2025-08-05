from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from flow.record.adapter import AbstractWriter
from flow.record.base import RecordWriter

if TYPE_CHECKING:
    from flow.record.base import Record


DEFAULT_RECORD_COUNT = 1000
DEFAULT_SUFFIX_LENGTH = 2

__usage__ = f"""
Record split adapter, splits records into multiple destination files (writer only)
---
Write usage: rdump -w split://[PATH]?count=[COUNT]&suffix-length=[SUFFIX-LENGTH]
[PATH]: output path or uri
[COUNT]: maximum record count per file (default: {DEFAULT_RECORD_COUNT})
[SUFFIX-LENGTH]: length of suffix (default: {DEFAULT_SUFFIX_LENGTH})
"""


class SplitWriter(AbstractWriter):
    writer = None

    def __init__(self, path: str | Path, **kwargs):
        self.path = str(path)
        self.kwargs = kwargs

        self.written = 0
        self.count = int(kwargs.get("count", DEFAULT_RECORD_COUNT))
        self.suffix_length = int(kwargs.get("suffix-length", DEFAULT_SUFFIX_LENGTH))
        self.file_count = 0

        parsed = urlparse(self.path)
        self.is_stdout = parsed.netloc in ("", "-") and parsed.path == ""

        self.writer = RecordWriter(self._next_path(), **self.kwargs)

    def _next_path(self) -> str:
        if self.is_stdout:
            return self.path

        path = self.path
        scheme = ""
        sep = ""
        if "://" in path:
            scheme, sep, path = path.partition("://")

        suffix = str(self.file_count).rjust(self.suffix_length, "0")
        path = Path(path)
        path = path.with_suffix(f".{suffix}{path.suffix}")

        self.file_count += 1
        return scheme + sep + str(path)

    def write(self, r: Record) -> None:
        self.writer.write(r)

        if self.is_stdout:
            return

        self.written += 1
        if self.written >= self.count:
            self.flush()
            self.close()
            self.written = 0
            self.writer = RecordWriter(self._next_path(), **self.kwargs)

    def flush(self) -> None:
        if self.writer:
            self.writer.flush()

    def close(self) -> None:
        if self.writer:
            self.writer.close()
        self.writer = None
