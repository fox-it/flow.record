from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from flow.record import open_path_or_stream
from flow.record.adapter import AbstractWriter
from flow.record.utils import is_stdout

if TYPE_CHECKING:
    from pathlib import Path

    from flow.record.base import Record

__usage__ = """
Textual output adapter, similar to `repr()` (writer only)
---
Write usage: rdump -w text://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""

REPLACE_LIST = [
    (r"\r", "\r"),
    (r"\n", "\n"),
    (r"\t", "\t"),
]


class DefaultMissing(dict):
    """A dictionary subclass that returns a formatted string for missing keys.

    Example:
        >>> d = DefaultMissing({"foo": "bar"})
        >>> d["foo"]
        'bar'
        >>> d["missing_key"]
        '{missing_key}'
    """

    def __missing__(self, key: str) -> str:
        return key.join("{}")


class TextWriter(AbstractWriter):
    """Records are printed as textual representation with repr() or using `format_spec`."""

    fp = None

    def __init__(self, path: str | Path | BinaryIO, flush: bool = True, format_spec: str | None = None, **kwargs):
        self.fp = open_path_or_stream(path, "wb")
        self.auto_flush = flush
        self.format_spec = format_spec

        # Allow some special characters in format template
        if self.format_spec:
            for old, new in REPLACE_LIST:
                self.format_spec = self.format_spec.replace(old, new)

    def write(self, rec: Record) -> None:
        buf = self.format_spec.format_map(DefaultMissing(rec._asdict())) if self.format_spec else repr(rec)
        self.fp.write(buf.encode(errors="surrogateescape") + b"\n")

        # because stdout is usually line buffered we force flush here if wanted
        if self.auto_flush:
            self.flush()

    def flush(self) -> None:
        if self.fp:
            self.fp.flush()

    def close(self) -> None:
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
