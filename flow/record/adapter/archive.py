from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.stream import RecordArchiver

if TYPE_CHECKING:
    from flow.record.base import Record

__usage__ = """
Record archiver adapter, writes records to YYYY/mm/dd directories (writer only)
---
Write usage: rdump -w archive://[PATH]
[PATH]: path to folder
"""


class ArchiveWriter(AbstractWriter):
    writer = None

    def __init__(self, path: str, **kwargs):
        self.path = path

        path_template = kwargs.get("path_template")
        name = kwargs.get("name")

        self.writer = RecordArchiver(self.path, path_template=path_template, name=name)

    def write(self, r: Record) -> None:
        self.writer.write(r)

    def flush(self) -> None:
        # RecordArchiver already flushes after every write
        pass

    def close(self) -> None:
        if self.writer:
            self.writer.close()
        self.writer = None


class ArchiveReader(AbstractReader):
    def __init__(self, path: str, **kwargs):
        raise NotImplementedError
