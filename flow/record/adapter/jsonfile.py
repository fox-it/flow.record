import json
from flow import record
from flow.record import JsonRecordPacker
from flow.record.utils import is_stdout
from flow.record.selector import make_selector
from flow.record.adapter import AbstractWriter, AbstractReader
from flow.record.fieldtypes import fieldtype_for_value

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

    def __init__(self, path, indent=None, descriptors=True, **kwargs):
        self.descriptors = str(descriptors).lower() in ("true", "1")
        self.fp = record.open_path(path, "w")
        if isinstance(indent, str):
            indent = int(indent)
        self.packer = JsonRecordPacker(indent=indent, pack_descriptors=self.descriptors)
        if self.descriptors:
            self.packer.on_descriptor.add_handler(self.packer_on_new_descriptor)

    def packer_on_new_descriptor(self, descriptor):
        self._write(descriptor)

    def _write(self, obj):
        record_json = self.packer.pack(obj)
        self.fp.write(record_json + "\n")

    def write(self, r):
        self._write(r)

    def flush(self):
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class JsonfileReader(AbstractReader):
    fp = None

    def __init__(self, path, selector=None, **kwargs):
        self.selector = make_selector(selector)
        self.fp = record.open_path(path, "r")
        self.packer = JsonRecordPacker()

    def close(self):
        if self.fp:
            self.fp.close()
        self.fp = None

    def __iter__(self):
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
