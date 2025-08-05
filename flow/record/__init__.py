from __future__ import annotations

import gzip
from pathlib import Path

from flow.record.base import (
    IGNORE_FIELDS_FOR_COMPARISON,
    RECORD_VERSION,
    RECORDSTREAM_MAGIC,
    DynamicDescriptor,
    FieldType,
    GroupedRecord,
    Record,
    RecordAdapter,
    RecordDescriptor,
    RecordDescriptorError,
    RecordField,
    RecordReader,
    RecordWriter,
    dynamic_fieldtype,
    extend_record,
    ignore_fields_for_comparison,
    iter_timestamped_records,
    open_path,
    open_path_or_stream,
    open_stream,
    set_ignored_fields_for_comparison,
    stream,
)
from flow.record.jsonpacker import JsonRecordPacker
from flow.record.stream import (
    PathTemplateWriter,
    RecordArchiver,
    RecordOutput,
    RecordPacker,
    RecordPrinter,
    RecordStreamReader,
    RecordStreamWriter,
    record_stream,
)

__all__ = [
    "IGNORE_FIELDS_FOR_COMPARISON",
    "RECORDSTREAM_MAGIC",
    "RECORD_VERSION",
    "DynamicDescriptor",
    "FieldType",
    "GroupedRecord",
    "JsonRecordPacker",
    "PathTemplateWriter",
    "Record",
    "RecordAdapter",
    "RecordArchiver",
    "RecordDescriptor",
    "RecordDescriptorError",
    "RecordField",
    "RecordOutput",
    "RecordPacker",
    "RecordPrinter",
    "RecordReader",
    "RecordStreamReader",
    "RecordStreamWriter",
    "RecordWriter",
    "dynamic_fieldtype",
    "extend_record",
    "ignore_fields_for_comparison",
    "iter_timestamped_records",
    "open_path",
    "open_path_or_stream",
    "open_stream",
    "record_stream",
    "set_ignored_fields_for_comparison",
    "stream",
]


class RecordDateSplitter:
    basepath = None
    out = None

    def __init__(self, basepath: str | Path):
        self.basepath = Path(basepath)
        self.out = {}

    def getstream(self, t: tuple[int, int, int]) -> RecordStreamWriter:
        if t not in self.out:
            path = self.basepath.joinpath("-".join([f"{v:2d}" for v in t]) + ".rec.gz")
            f = gzip.GzipFile(path, "wb")
            rs = RecordStreamWriter(f)
            self.out[t] = rs
        return self.out[t]

    def write(self, r: Record) -> None:
        t = (r.ts.year, r.ts.month, r.ts.day)
        rs = self.getstream(t)
        rs.write(r)
        rs.fp.flush()

    def close(self) -> None:
        for rs in self.out.values():
            rs.close()
