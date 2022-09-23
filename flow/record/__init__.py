import gzip
import os

from flow.record.base import (
    RECORD_VERSION,
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
    open_path,
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
    "RECORD_VERSION",
    "FieldType",
    "Record",
    "GroupedRecord",
    "RecordDescriptor",
    "RecordAdapter",
    "RecordField",
    "RecordReader",
    "RecordWriter",
    "RecordOutput",
    "RecordPrinter",
    "RecordPacker",
    "JsonRecordPacker",
    "RecordStreamWriter",
    "RecordStreamReader",
    "open_path",
    "stream",
    "dynamic_fieldtype",
    "DynamicDescriptor",
    "PathTemplateWriter",
    "RecordArchiver",
    "RecordDescriptorError",
    "record_stream",
    "extend_record",
]


class View:
    fields = None

    def __init__(self, fields):
        self.fields = fields

    def __iter__(self, fields):
        pass


class RecordDateSplitter:
    basepath = None
    out = None

    def __init__(self, basepath):
        self.basepath = basepath
        self.out = {}

    def getstream(self, t):
        if t not in self.out:
            path = os.path.join(self.basepath, "-".join(["{:2d}".format(v) for v in t]) + ".rec.gz")
            f = gzip.GzipFile(path, "wb")
            rs = RecordStreamWriter(f)
            self.out[t] = rs
        return self.out[t]

    def write(self, r):
        t = (r.ts.year, r.ts.month, r.ts.day)
        rs = self.getstream(t)
        rs.write(r)
        rs.fp.flush()

    def close(self):
        for rs in self.out.values():
            rs.close()
