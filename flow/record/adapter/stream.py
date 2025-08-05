from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record import Record, RecordOutput, RecordStreamReader, open_path_or_stream
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.utils import is_stdout

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.selector import Selector

__usage__ = """
Binary stream adapter (default adapter if none are specified)
---
Write usage: rdump -w stream://[PATH]
Read usage: rdump stream://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""


class StreamWriter(AbstractWriter):
    fp = None
    stream = None

    def __init__(self, path: str, clobber: bool = True, **kwargs):
        self.fp = open_path_or_stream(path, "wb", clobber=clobber)
        self.stream = RecordOutput(self.fp)

    def write(self, record: Record) -> None:
        self.stream.write(record)

    def flush(self) -> None:
        if self.stream and hasattr(self.stream, "flush"):
            self.stream.flush()
        if self.fp:
            self.fp.flush()

    def close(self) -> None:
        if self.stream:
            self.stream.close()
        self.stream = None

        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class StreamReader(AbstractReader):
    fp = None
    stream = None

    def __init__(self, path: str, selector: str | Selector = None, **kwargs):
        self.fp = open_path_or_stream(path, "rb")
        self.stream = RecordStreamReader(self.fp, selector=selector)

    def __iter__(self) -> Iterator[Record]:
        return iter(self.stream)

    def close(self) -> None:
        if self.stream:
            self.stream.close()
        self.stream = None

        if self.fp:
            self.fp.close()
        self.fp = None
