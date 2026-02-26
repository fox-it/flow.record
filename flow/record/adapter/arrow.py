from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING, BinaryIO, Literal

import pyarrow as pa

from flow.record import Record, RecordDescriptor, open_path_or_stream
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.context import get_app_context, match_record_with_context
from flow.record.selector import Selector, make_selector

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record


DEFAULT_BATCH_SIZE = 1000
DEFAULT_COMPRESSION = "zstd"

__usage__ = f"""
Apache Arrow adapter
---
Write usage: rdump -w arrow://[PATH]?batch_size=[BATCH_SIZE]&compression=[COMPRESSION]
Read usage: rdump arrow://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout

Optional parameters:
    [BATCH_SIZE]: number of records to write in a single batch (default: {DEFAULT_BATCH_SIZE})
    [COMPRESSION]: compression algorithm to use: "zstd", "lz4", or "none" (default: {DEFAULT_COMPRESSION})
"""

log = logging.getLogger(__name__)

# Mapping of flow.record field types to pyarrow types.
ARROW_TYPE_MAP = {
    "boolean": pa.bool_(),
    "datetime": pa.timestamp("us", tz="UTC"),
    "filesize": pa.uint64(),
    "uint8": pa.uint8(),
    "uint16": pa.uint16(),
    "uint32": pa.uint32(),
    "float": pa.float64(),
    "string": pa.string(),
    "unix_file_mode": pa.uint16(),
    "varint": pa.int64(),  # use int64 for varint, not ideal but Arrow has no varint type
    "wstring": pa.string(),
    "uri": pa.string(),
    "digest": pa.struct(
        {
            "md5": pa.binary(length=16),
            "sha1": pa.binary(length=20),
            "sha256": pa.binary(length=32),
        }
    ),
    "bytes": pa.binary(),
}

# Mapping of pyarrow type checks to flow.record field types.
RECORD_TYPE_MAP = {
    pa.types.is_floating: "float",
    pa.types.is_integer: "varint",
    pa.types.is_boolean: "boolean",
    pa.types.is_binary: "bytes",
    pa.types.is_timestamp: "datetime",
    pa.types.is_string: "string",
}


def descriptor_to_arrow_schema(descriptor: RecordDescriptor) -> pa.Schema:
    """Convert a flow.record RecordDescriptor to a pyarrow Schema."""
    fields = []
    for field_name, field_type in descriptor.get_all_fields().items():
        log.debug("Mapping field '%s' of type '%s' to Arrow type", field_name, field_type)
        type_name = field_type.typename
        pa_type = ARROW_TYPE_MAP.get(type_name, pa.string())
        fields.append(pa.field(field_name, pa_type))

    metadata = {
        b"descriptor_name": descriptor.name.encode("utf-8"),
        b"descriptor_fields": ",".join(f"{fname}:{ftype}" for ftype, fname in descriptor.get_field_tuples()).encode(
            "utf-8"
        ),
    }
    log.debug("Arrow schema metadata: %s", metadata)
    return pa.schema(fields, metadata=metadata)


def as_pyarrowdict(record: Record) -> dict:
    """Convert a Record to a dictionary with values compatible with pyarrow."""
    desc = record._desc
    d = record._asdict()
    for field in desc.getfields("digest", all_fields=True):
        value = d[field.name]
        if value is not None:
            d[field.name] = dict(value)
    return d


def arrow_schema_to_descriptor(schema: pa.Schema) -> RecordDescriptor:
    """Convert a pyarrow Schema to a flow.record RecordDescriptor."""

    # Check for embedded flow.record descriptor metadata
    metadata = schema.metadata or {}
    descriptor_name = metadata.get(b"descriptor_name", b"arrow/record").decode("utf-8")
    if descriptor_fields := metadata.get(b"descriptor_fields", b"").decode("utf-8"):
        fields = [
            (ftype, name) for field_def in descriptor_fields.split(",") for name, ftype in [field_def.split(":", 1)]
        ]
        log.debug("Extracted embedded descriptor fields: %s", fields)
        return RecordDescriptor(name=descriptor_name, fields=fields)

    # No embedded descriptor, attempt to generate one from the schema
    fields = []
    for field in schema:
        # Skip internal fields
        if field.startswith("_"):
            continue

        pa_type = field.type
        log.debug("Mapping Arrow field %r of type %r to flow.record type", field.name, pa_type)

        # Find matching typename
        typename = next(
            (typename for check, typename in RECORD_TYPE_MAP.items() if check(pa_type)),
            "string",
        )
        fields.append((typename, field.name))

    return RecordDescriptor(name=descriptor_name, fields=fields)


class ArrowWriter(AbstractWriter):
    def __init__(
        self,
        path: str,
        *,
        batch_size: str | int = 1000,
        compression: Literal["zstd", "lz4", "none"] | None = "zstd",
        **kwargs,
    ):
        self.path = path
        self.compression = compression
        self.batch_size = int(batch_size)
        self.descriptors_seen = set()
        self.current_descriptor: RecordDescriptor | None = None
        self.batch: list[Record] = []
        self.schema = None

        if self.compression and self.compression.lower() == "none":
            self.compression = None

        self.fp = open_path_or_stream(path, "wb")
        self.stream_writer = None

        self.ipc_options = pa.ipc.IpcWriteOptions(compression=self.compression)

    def write(self, record: Record) -> None:
        """Write a record to the database"""

        # if this is a new descriptor, flush existing batch and create new schema
        descriptor = record._desc
        if descriptor != self.current_descriptor:
            self.flush()
            self.current_descriptor = descriptor
            self.schema = descriptor_to_arrow_schema(descriptor)
            self.stream_writer = pa.ipc.new_stream(self.fp, self.schema, options=self.ipc_options)

        self.batch.append(record)

        # Commit every batch_size records
        if len(self.batch) % self.batch_size == 0:
            self.flush()

    def close(self) -> None:
        self.flush()
        if self.fp:
            self.fp.close()

    def flush(self) -> None:
        log.debug("Flushing %d records to Arrow stream (%r)", len(self.batch), self.stream_writer)
        if self.batch:
            batch = pa.Table.from_pylist(
                [as_pyarrowdict(r) for r in self.batch],
                schema=self.schema,
            )
            self.stream_writer.write_table(batch)
            self.batch = []


def iter_record_batch(stream: pa.RecordBatchReader, fp: BinaryIO) -> Iterator[pa.RecordBatch]:
    """Iterate over RecordBatches from a RecordBatchReader.

    Argument:
        stream: Arrow RecordBatchReader

    Yields:
        Arrow RecordBatch
    """
    while True:
        try:
            # check for end of batch stream
            msg_type = fp.peek(10)[8:9]
            log.info("Message type: %s", msg_type)
            if msg_type != b"\x14":
                break
            batch = stream.read_next_batch()
            log.debug("Read RecordBatch with %d rows", batch.num_rows)
            yield batch
        except StopIteration:
            break


def iter_ipc_streams(fp: BinaryIO) -> Iterator[pa.RecordBatchReader]:
    """Iterate over Arrow IPC streams from a file-like object.

    This handles multiple streams in a single file. And thus multiple schemas.
    Note: pyarrow does not have a built-in way to handle multiple streams in a single file,
    so we attempt to open streams until we reach the end of the file.

    Argument:
        fp: file-like object to read from

    Yields:
        Arrow RecordBatchReader for each stream
    """

    # keep trying to open streams until we reach end of file or get an invalid stream
    with contextlib.suppress(pa.ArrowInvalid):
        while True:
            log.debug("Opening stream at position: %s", fp.tell())
            stream = pa.ipc.open_stream(fp)
            yield stream


class ArrowReader(AbstractReader):
    """Apache Arrow reader.

    This supports reading multiple Arrow IPC streams from a single file.
    However, this is not commonly supported by other tools.

    It supports flow.record embedded RecordDescriptor metadata for accurate type mapping.
    Otherwise, it will attempt to infer types from Arrow schema.
    """

    def __init__(self, path: str, selector: Selector | str | None = None, **kwargs):
        self.path = path
        self.selector = make_selector(selector)
        self.fp = open_path_or_stream(path, "rb")

    def close(self) -> None:
        log.info("Closing ArrowReader for path: %s", self.path)
        if self.fp:
            self.fp.close()

    def __iter__(self) -> Iterator[Record]:
        ctx = get_app_context()
        selector = self.selector

        for stream in iter_ipc_streams(self.fp):
            log.debug("Reading new Arrow IPC stream with schema: %s", stream.schema)
            for batch in iter_record_batch(stream, self.fp):
                # Convert descriptor once per batch, not per row
                descriptor = arrow_schema_to_descriptor(batch.schema)

                # Use to_pydict() for columnar access, more efficient for large batches
                batch_dict = batch.to_pydict()
                num_rows = len(next(iter(batch_dict.values())))

                for i in range(num_rows):
                    row_dict = {k: v[i] for k, v in batch_dict.items()}
                    record = descriptor.init_from_dict(row_dict)
                    if match_record_with_context(record, selector, ctx):
                        yield record
