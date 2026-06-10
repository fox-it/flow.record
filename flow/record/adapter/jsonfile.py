from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, BinaryIO

from flow import record
from flow.record import JsonRecordPacker
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.context import get_app_context, match_record_with_context
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


log = logging.getLogger(__name__)


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

    def __init__(
        self, path: str | Path | BinaryIO, selector: str | None = None, record_name: str = "json/record", **kwargs
    ):
        self.selector = make_selector(selector)
        self.fp = record.open_path_or_stream(path, "r")
        self.packer = JsonRecordPacker()
        self.record_name = record_name

    def close(self) -> None:
        if self.fp:
            self.fp.close()
        self.fp = None

    def obj_hook(self, obj: record.Record | dict) -> Any:
        return obj

    def __iter__(self) -> Iterator[Record]:
        ctx = get_app_context()
        selector = self.selector

        if not self.fp:
            return

        for line in self.fp:
            if not line or line == "\n":
                continue

            try:
                obj = self.packer.unpack(line)
            except Exception as e:
                log.warning("Failed unpacking line '%s'", line)
                log.debug("", exc_info=e)
                continue

            if isinstance(obj, record.RecordDescriptor):
                continue

            elif isinstance(obj, record.Record) and match_record_with_context(obj, selector, ctx):
                yield self.obj_hook(obj)

            elif isinstance(obj, dict):
                obj = self.obj_hook(obj)

                fields = [
                    (fieldtype_for_value(val, "string"), key) for key, val in obj.items() if not key.startswith("_")
                ]
                desc = record.RecordDescriptor(self.record_name, fields)
                obj = desc(**obj)
                if match_record_with_context(obj, selector, ctx):
                    yield obj

            else:
                log.warning("Failed handling unpacked line '%s'", line)
