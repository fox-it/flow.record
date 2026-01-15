from __future__ import annotations

import logging
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import pyarrow as pa
import pyarrow.parquet as pq

from flow.record import Record, RecordDescriptor, fieldtypes, open_path_or_stream
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import is_valid_field_name
from flow.record.context import get_app_context, match_record_with_context
from flow.record.selector import Selector, make_selector

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record

DEFAULT_BATCH_SIZE = 1000
DEFAULT_COMPRESSION = "zstd"

__usage__ = f"""
Apache Parquet adapter
---
Write usage: rdump -w parquet://[PATH]?batch_size=[BATCH_SIZE]&compression=[COMPRESSION]
Read usage: rdump parquet://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout

Optional parameters:
    [BATCH_SIZE]: number of records to write in a single batch (default: {DEFAULT_BATCH_SIZE})
    [COMPRESSION]: compression algorithm to use: "snappy", "gzip", "brotli", "zstd", "lz4", or "none" (default: {DEFAULT_COMPRESSION})
"""  # noqa: E501

log = logging.getLogger(__name__)


# Mapping of flow.record field type names to pyarrow types.
RECORD_TO_ARROW_TYPE_MAP = {
    "boolean": pa.bool_(),
    "datetime": pa.timestamp("us", tz="UTC"),
    "filesize": pa.uint64(),
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
    "path": pa.struct(
        {
            "path": pa.string(),
            "path_type": pa.uint8(),
        }
    ),
}

# Mapping of pyarrow type checks to flow.record field type names
# This is only used when there is no known RecordDescriptor schema available
ARROW_TO_RECORD_TYPE_MAP = {
    pa.types.is_floating: "float",
    pa.types.is_uint16: "uint16",
    pa.types.is_uint32: "uint32",
    pa.types.is_integer: "varint",
    pa.types.is_boolean: "boolean",
    pa.types.is_binary: "bytes",
    pa.types.is_timestamp: "datetime",
    pa.types.is_string: "string",
}


@lru_cache(maxsize=128)
def get_fieldnames_for_fieldtype(descriptor: RecordDescriptor, fieldtype: str) -> list[str]:
    """Get a list of field names in the descriptor that match the given field type.

    Argument:
        descriptor: RecordDescriptor to search
        fieldtype: field type to match
    Returns:
        List of field names matching the field type
    """
    return [fname for ftype, fname in descriptor.get_field_tuples() if ftype == fieldtype]  # type: ignore


@lru_cache(maxsize=128)
def descriptor_to_arrow_schema(descriptor: RecordDescriptor) -> pa.Schema:
    """Convert a flow.record RecordDescriptor to a pyarrow Schema."""
    fields = []
    for field_name, field_type in descriptor.get_all_fields().items():
        log.debug("Mapping field %r of type %r to Arrow type", field_name, field_type)
        type_name = field_type.typename
        pa_type = RECORD_TO_ARROW_TYPE_MAP.get(type_name, pa.string())
        fields.append(pa.field(field_name, pa_type))

    metadata = {
        b"descriptor_name": descriptor.name.encode("utf-8"),
        b"descriptor_fields": ",".join(f"{fname}:{ftype}" for ftype, fname in descriptor.get_field_tuples()).encode(
            "utf-8"
        ),
    }
    log.debug("Arrow schema metadata: %s", metadata)
    return pa.schema(fields, metadata=metadata)


@lru_cache(maxsize=128)
def record_to_pyarrowdict(record: Record) -> dict:
    """Convert a Record to a dictionary with values compatible with pyarrow.

    Arguments:
        record: Record to convert

    Returns:
        Dictionary with pyarrow-compatible values
    """
    desc = record._desc
    d = record._asdict()

    # serialize path type
    for field in get_fieldnames_for_fieldtype(desc, "path"):
        if (value := d[field]) is not None:
            path, path_type = value._pack()
            d[field] = {"path": path, "path_type": path_type}

    # serialize digest type
    for field in get_fieldnames_for_fieldtype(desc, "digest"):
        if (value := d[field]) is not None:
            md5, sha1, sha256 = value._pack()
            d[field] = {"md5": md5, "sha1": sha1, "sha256": sha256}

    return d


def pyarrowdict_to_record(
    row_dict: dict,
    descriptor: RecordDescriptor,
    rename_fields: dict[str, str] | None = None,
) -> Record:
    """Convert a pyarrow row dictionary to a Record, handling special field types.

    Arguments:
        row_dict: dictionary of field values from pyarrow
        descriptor: RecordDescriptor to use for creating the Record
        rename_fields: optional mapping of original field names to renamed field names

    Returns:
        Record created from the pyarrow row dictionary
    """
    # deserialize path type
    for field in get_fieldnames_for_fieldtype(descriptor, "path"):
        if (value := row_dict.get(field)) is not None:
            row_dict[field] = fieldtypes.path._unpack(data=(value["path"], value["path_type"]))

    # deserialize digest type
    for field in get_fieldnames_for_fieldtype(descriptor, "digest"):
        if (value := row_dict.get(field)) is not None:
            row_dict[field] = fieldtypes.digest._unpack(data=(value["md5"], value["sha1"], value["sha256"]))

    # it's possible that some field names were renamed to be valid flow.record field names, remap them here
    if rename_fields:
        for old_key, new_key in rename_fields.items():
            if old_key in row_dict:
                row_dict[new_key] = row_dict.pop(old_key)

    return descriptor.init_from_dict(row_dict)


@lru_cache(maxsize=128)
def arrow_schema_to_descriptor(
    schema: pa.Schema,
) -> tuple[RecordDescriptor, dict[str, str]]:
    """Convert a pyarrow Schema to a flow.record RecordDescriptor.

    This function also returns a mapping of original field names to renamed field names
    in case any field names were modified to be valid flow.record field names. For example,
    spaces and special characters are replaced with underscores. This mapping can be used
    when reading records to ensure the field names match those in the descriptor.

    Argument:
        schema: pyarrow Schema to convert

    Returns:
        RecordDescriptor and mapping of original field names to renamed field names
    """

    # Check for embedded flow.record descriptor metadata
    metadata = schema.metadata or {}
    descriptor_name = metadata.get(b"descriptor_name", b"parquet/record").decode("utf-8")
    if descriptor_fields := metadata.get(b"descriptor_fields", b"").decode("utf-8"):
        fields = [
            (ftype, name) for field_def in descriptor_fields.split(",") for name, ftype in [field_def.split(":", 1)]
        ]
        log.debug("Extracted embedded descriptor fields: %s", fields)
        return RecordDescriptor(name=descriptor_name, fields=fields), {}

    # No embedded descriptor, attempt to generate one from the schema
    fields = []
    field_name_mappings = {}
    for field in schema:
        field_type = field.type
        field_name = field.name

        # replace common invalid characters in field names
        original_field_name = field_name
        field_name = original_field_name.replace(" ", "_").replace("-", "_").replace(".", "_")

        # Skip reserved or invalid field names
        if not is_valid_field_name(field_name):
            log.warning(
                "Dropping invalid field name in Arrow schema: %r (original: %r)",
                field_name,
                original_field_name,
            )
            continue

        if field_name != original_field_name:
            log.debug("Renaming field %r to %r for flow.record compatibility", original_field_name, field_name)
            field_name_mappings[original_field_name] = field_name

        log.debug(
            "Mapping Arrow field %r of type %r to flow.record type",
            field_name,
            field_type,
        )

        # Find matching typename
        typename = next(
            (typename for check, typename in ARROW_TO_RECORD_TYPE_MAP.items() if check(field_type)),
            "string",
        )
        fields.append((typename, field_name))

    return RecordDescriptor(name=descriptor_name, fields=fields), field_name_mappings


class ParquetWriter(AbstractWriter):
    def __init__(
        self,
        path: str,
        *,
        batch_size: str | int = DEFAULT_BATCH_SIZE,
        compression: (Literal["snappy", "gzip", "brotli", "zstd", "lz4", "none"] | None) = "zstd",
        **kwargs,
    ):
        self.path = Path(path)
        self.compression = compression
        self.batch_size = int(batch_size)
        self.descriptors_seen = set()
        self.batch: list[Record] = []
        self.schema = None

        if compression.lower() == "none":
            self.compression = None

        # self.fp = open_path_or_stream(path, "wb")
        self.stream_writer = None
        self.parquet_writers = {}
        self.writer_batch: defaultdict[tuple[str, int], list[Record]] = defaultdict(list)

    def write(self, record: Record) -> None:
        """Write a record to the current batch. Flushes the batch to disk if ``batch_size`` is reached.

        Note: This implementation creates separate Parquet files for each RecordDescriptor.
        This is because Parquet files only support a single schema per file. The first descriptor uses the given path,
        and subsequent descriptors create new files with unique names based on the descriptor.

        Argument:
            record: Record to write
        """
        descriptor = record._desc

        # if this is a new descriptor, create a new ParquetWriter
        if descriptor.identifier not in self.parquet_writers:
            schema = descriptor_to_arrow_schema(descriptor)

            # First time seeing this descriptor, create a new ParquetWriter
            output_path = self.path

            # Create unique output path if multiple descriptors are seen
            if len(self.parquet_writers) > 0:
                desc_id = f"{descriptor.name.replace('/', '_')}_{descriptor.descriptor_hash:x}"
                output_path = self.path.with_stem(self.path.stem + f"_{desc_id}")

            # Create and register ParquetWriter
            writer = pq.ParquetWriter(
                output_path,
                schema=schema,
                compression=self.compression,
            )
            self.parquet_writers[descriptor.identifier] = writer

        # Add record to the descriptor-specific batch
        self.writer_batch[descriptor.identifier].append(record)

        # Commit every batch_size records
        if len(self.writer_batch[descriptor.identifier]) % self.batch_size == 0:
            self.flush_writer(descriptor.identifier)

    def close(self) -> None:
        """Flush and close any open Parquet writers."""
        for identifier, writer in self.parquet_writers.items():
            self.flush_writer(identifier)
            writer.close()

        self.parquet_writers.clear()
        self.writer_batch.clear()

    def flush_writer(self, indentifier: tuple[str, int]) -> None:
        """Flush the record batch of the Parquet writer identified by ``identifier`` to disk."""
        batch_records = self.writer_batch[indentifier]
        if not batch_records:
            return

        descriptor = batch_records[0]._desc
        table = pa.Table.from_pylist(
            [record_to_pyarrowdict(r) for r in batch_records],
            schema=descriptor_to_arrow_schema(descriptor),
        )
        writer = self.parquet_writers[indentifier]
        writer.write_table(table)
        self.writer_batch[indentifier] = []

    def flush(self) -> None:
        """Flush the current record batch to disk for all descriptors."""
        for identifier in list(self.writer_batch.keys()):
            self.flush_writer(identifier)


class ParquetReader(AbstractReader):
    """Apache Parquet reader."""

    def __init__(
        self,
        path: str,
        selector: Selector | str | None = None,
        fields: list[str] | str | None = None,
        exclude: list[str] | str | None = None,
        **kwargs,
    ):
        self.path = path
        self.selector = make_selector(selector)

        self.fields = fields
        self.exclude = exclude
        if isinstance(self.fields, str):
            self.fields = self.fields.split(",")
        if isinstance(self.exclude, str):
            self.exclude = self.exclude.split(",")

        source = open_path_or_stream(path, "rb") if path in (None, "", "-") else path
        self.parquet_file = pq.ParquetFile(source)
        self.num_rows = self.parquet_file.metadata.num_rows
        log.info(
            "Opened Parquet file with %u of rows (%u row groups).",
            self.num_rows,
            self.parquet_file.num_row_groups,
        )

    def close(self) -> None:
        log.info("Closing ParquetReader for path: %s", self.path)
        if self.parquet_file:
            self.parquet_file.close()
            self.parquet_file = None

    def __iter__(self) -> Iterator[Record]:
        ctx = get_app_context()
        selector = self.selector
        descriptor, field_name_mappings = arrow_schema_to_descriptor(self.parquet_file.schema_arrow)

        # determine which descriptor columns to read based on fields/exclude
        columns = None
        if self.fields or self.exclude:
            columns = set(descriptor.get_all_fields())
            if self.fields:
                columns = columns & set(self.fields)
            if self.exclude:
                columns = columns - set(self.exclude)
            log.debug("Reading Parquet columns: %r", columns)

        for row_group_idx in range(self.parquet_file.num_row_groups):
            table = self.parquet_file.read_row_group(row_group_idx, columns=columns)
            batch_dict = table.to_pydict()
            num_rows = len(next(iter(batch_dict.values())))

            for i in range(num_rows):
                row_dict = {k: v[i] for k, v in batch_dict.items()}
                record = pyarrowdict_to_record(
                    row_dict,
                    descriptor=descriptor,
                    rename_fields=field_name_mappings,
                )
                if match_record_with_context(record, selector, ctx):
                    yield record
