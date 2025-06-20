from __future__ import annotations

import json
from typing import TYPE_CHECKING, BinaryIO

from flow import record
from flow.record import JsonRecordPacker
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.fieldtypes import fieldtype_for_value
from flow.record.selector import make_selector
from flow.record.utils import boolean_argument, is_stdout

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from flow.record.base import Record, RecordDescriptor

__usage__ = """
JSON adapter
---
Write usage: rdump -w jsonfile://[PATH]?indent=[INDENT]&descriptors=[DESCRIPTORS]
Read usage: rdump jsonfile://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
[INDENT]: optional number of identation. Omit "indent" field value for jsonlines output
[DESCRIPTORS]: optional boolean. If false, don't output record descriptors (default: true)
"""


class JsonfileWriter(AbstractWriter):
    fp = None

    def __init__(
        self, path: str | Path | BinaryIO, indent: str | int | None = None, descriptors: bool = True, **kwargs
    ):
        self.descriptors = boolean_argument(descriptors)
        self.fp = record.open_path_or_stream(path, "w")
        if isinstance(indent, str):
            indent = int(indent)
        self.packer = JsonRecordPacker(indent=indent, pack_descriptors=self.descriptors)
        if self.descriptors:
            self.packer.on_descriptor.add_handler(self.packer_on_new_descriptor)

    def packer_on_new_descriptor(self, descriptor: RecordDescriptor) -> None:
        self._write(descriptor)

    def _write(self, obj: Record | RecordDescriptor) -> None:
        record_json = self.packer.pack(obj)
        self.fp.write(record_json + "\n")

    def write(self, r: Record) -> None:
        self._write(r)

    def flush(self) -> None:
        if self.fp:
            self.fp.flush()

    def close(self) -> None:
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class JsonfileReader(AbstractReader):
    fp = None

    def __init__(self, path: str | Path | BinaryIO, selector: str | None = None, **kwargs):
        self.selector = make_selector(selector)
        self.fp = record.open_path_or_stream(path, "r")
        self.packer = JsonRecordPacker()

    def close(self) -> None:
        if self.fp:
            self.fp.close()
        self.fp = None

    def __iter__(self) -> Iterator[Record]:
        for line in self.fp:
            obj = self.packer.unpack(line)
            if isinstance(obj, record.Record):
                if not self.selector or self.selector.match(obj):
                    yield obj
            elif isinstance(obj, record.RecordDescriptor):
                pass
            else:
                # fallback for plain jsonlines (non flow.record format)
                jd = json.loads(line)
                fields = [
                    (fieldtype_for_value(val, "string"), key) for key, val in jd.items() if not key.startswith("_")
                ]
                desc = record.RecordDescriptor("json/record", fields)
                obj = desc(**jd)
                if not self.selector or self.selector.match(obj):
                    yield obj
