import json
from datetime import datetime, timedelta, timezone
from importlib.util import find_spec

import fastavro

from flow import record
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.selector import make_selector
from flow.record.utils import is_stdout

__usage__ = """
Apache AVRO adapter
---
Write usage: rdump -w avro://[PATH]
Read usage: rdump avro://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""

AVRO_TYPE_MAP = {
    "boolean": "boolean",
    "datetime": "long",
    "filesize": "long",
    "uint16": "int",
    "uint32": "int",
    "float": "float",
    "string": "string",
    "unix_file_mode": "long",
    "varint": "long",
    "wstring": "string",
    "uri": "string",
    "digest": "bytes",
    "bytes": "bytes",
}

RECORD_TYPE_MAP = {
    "boolean": "boolean",
    "int": "varint",
    "long": "varint",
    "float": "float",
    "string": "string",
    "bytes": "bytes",
}

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class AvroWriter(AbstractWriter):
    fp = None
    writer = None

    def __init__(self, path, key=None, **kwargs):
        self.fp = record.open_path(path, "wb")

        self.desc = None
        self.schema = None
        self.parsed_schema = None
        self.writer = None
        self.codec = "snappy" if find_spec("snappy") else "deflate"

    def write(self, r):
        if not self.desc:
            self.desc = r._desc
            self.schema = descriptor_to_schema(self.desc)
            self.parsed_schema = fastavro.parse_schema(self.schema)
            self.writer = fastavro.write.Writer(self.fp, self.parsed_schema, codec=self.codec)

        if self.desc != r._desc:
            raise Exception("Mixed record types")

        self.writer.write(r._packdict())

    def flush(self):
        if self.writer:
            self.writer.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
        self.writer = None


class AvroReader(AbstractReader):
    fp = None

    def __init__(self, path, selector=None, **kwargs):
        self.fp = record.open_path(path, "rb")
        self.selector = make_selector(selector)

        self.reader = fastavro.reader(self.fp)
        self.schema = self.reader.schema
        if not self.schema:
            raise Exception("Missing Avro schema")

        self.desc = schema_to_descriptor(self.schema)

        # Store the fieldnames that are of type "datetime"
        self.datetime_fields = set(
            name for name, field in self.desc.get_all_fields().items() if field.typename == "datetime"
        )

    def __iter__(self):
        for obj in self.reader:
            # Convert timestamp-micros fields back to datetime fields
            for field_name in self.datetime_fields:
                value = obj.get(field_name, None)
                if isinstance(value, (int, float)) and value > 0xFFFFFFFF:
                    obj[field_name] = EPOCH + timedelta(microseconds=value)

            rec = self.desc.recordType(**obj)
            if not self.selector or self.selector.match(rec):
                yield rec

    def close(self):
        if self.fp:
            self.fp.close()
        self.fp = None


def descriptor_to_schema(desc):
    namespace, _, name = desc.name.rpartition("/")
    schema = {
        "type": "record",
        "namespace": namespace,
        "name": name,
        "doc": json.dumps(desc._pack()),
        "fields": [],
    }

    fields = []
    for rf in desc.get_all_fields().values():
        field_name = rf.name
        field_type = rf.typename
        field_schema = {
            "name": field_name,
        }

        if field_type == "datetime":
            field_schema["type"] = [{"type": "long", "logicalType": "timestamp-micros"}, {"type": "null"}]
        else:
            avro_type = AVRO_TYPE_MAP.get(field_type)
            if not avro_type:
                raise Exception("Unsupported Avro type: {}".format(field_type))

            field_schema["type"] = [avro_type, "null"]

        fields.append(field_schema)

    schema["fields"] = fields
    return schema


def schema_to_descriptor(schema):
    doc = schema.get("doc")

    # Sketchy record descriptor detection
    if doc and doc.startswith('["') and doc.endswith("]]]"):
        name, fields = json.loads(doc)
    else:
        # No embedded record descriptor, attempt to generate one from the schema
        name = "/".join([schema.get("namespace", ""), schema.get("name", "")]).replace(".", "/").strip("/")
        fields = []

        for f in schema.get("fields", []):
            field_name = f["name"]
            if field_name.startswith("_"):
                continue

            field_type = avro_type_to_flow_type(f["type"])
            fields.append([field_type, field_name])

    return record.RecordDescriptor(name, fields)


def avro_type_to_flow_type(ftype):
    ftypes = [ftype] if not isinstance(ftype, list) else ftype

    # If a field can be null, it has an additional type of "null"
    # So iterate over all the types, and break when we have a valid one
    for t in ftypes:
        if isinstance(t, dict):
            if t.get("type") == "array":
                item_type = avro_type_to_flow_type(t.get("items"))
                return "{}[]".format(item_type)
            else:
                logical_type = t.get("logicalType")
                if logical_type and "time" in logical_type or "date" in logical_type:
                    return "datetime"

        if t == "null":
            continue

        if t in RECORD_TYPE_MAP:
            return RECORD_TYPE_MAP[t]

    raise TypeError("Can't map avro type to flow type: {}".format(t))
