from __future__ import annotations

import datetime
import logging
import reprlib
import struct
import sys
from collections import ChainMap
from functools import lru_cache
from pathlib import Path
from typing import IO, TYPE_CHECKING, BinaryIO

from flow.record import RECORDSTREAM_MAGIC, RecordWriter
from flow.record.base import Record, RecordDescriptor, RecordReader
from flow.record.fieldtypes import fieldtype_for_value
from flow.record.packer import RecordPacker
from flow.record.selector import make_selector
from flow.record.utils import is_stdout

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.adapter import AbstractWriter

log = logging.getLogger(__package__)

aRepr = reprlib.Repr()
aRepr.maxother = 255


def RecordOutput(fp: IO) -> RecordPrinter | RecordStreamWriter:
    """Return a RecordPrinter if `fp` is a tty otherwise a RecordStreamWriter."""
    if hasattr(fp, "isatty") and fp.isatty():
        return RecordPrinter(fp)
    return RecordStreamWriter(fp)


class RecordPrinter:
    """Records are printed as textual representation (repr) to fp."""

    fp = None

    def __init__(self, fp: BinaryIO, flush: bool = True):
        self.fp = fp
        self.auto_flush = flush

    def write(self, obj: Record) -> None:
        buf = repr(obj).encode() + b"\n"
        self.fp.write(buf)
        if self.auto_flush:
            self.flush()

    def flush(self) -> None:
        self.fp.flush()

    def close(self) -> None:
        pass


class RecordStreamWriter:
    """Records are written as binary (serialized) to fp."""

    fp = None
    packer = None

    def __init__(self, fp: BinaryIO):
        self.fp = fp
        self.packer = RecordPacker()
        self.packer.on_descriptor.add_handler(self.on_new_descriptor)
        self.header_written = False

    def __del__(self) -> None:
        self.close()

    def on_new_descriptor(self, descriptor: RecordDescriptor) -> None:
        self.write(descriptor)

    def close(self) -> None:
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
            self.fp = None

    def flush(self) -> None:
        if not self.header_written:
            self.writeheader()

    def write(self, obj: Record | RecordDescriptor) -> None:
        if not self.header_written:
            self.writeheader()
        blob = self.packer.pack(obj)
        self.fp.write(struct.pack(">I", len(blob)))
        self.fp.write(blob)

    def writeheader(self) -> None:
        self.header_written = True
        self.write(RECORDSTREAM_MAGIC)


class RecordStreamReader:
    fp = None
    recordtype = None
    descs = None
    packer = None

    def __init__(self, fp: BinaryIO, selector: str | None = None):
        self.fp = fp
        self.closed = False
        self.selector = make_selector(selector)
        self.packer = RecordPacker()
        self.readheader()

    def readheader(self) -> None:
        # Manually read the msgpack format to avoid unserializing invalid data
        # we read size (4) + msgpack type (2) + msgpack bytes (recordstream magic)
        header = self.fp.read(4 + 2 + len(RECORDSTREAM_MAGIC))
        if not header.endswith(RECORDSTREAM_MAGIC):
            raise IOError("Unknown file format, not a RecordStream")

    def read(self) -> Record | RecordDescriptor:
        d = self.fp.read(4)
        if len(d) != 4:
            raise EOFError

        size = struct.unpack(">I", d)[0]
        d = self.fp.read(size)
        return self.packer.unpack(d)

    def close(self) -> None:
        self.closed = True

    def __iter__(self) -> Iterator[Record]:
        try:
            while not self.closed:
                obj = self.read()
                if obj == RECORDSTREAM_MAGIC:
                    continue
                if isinstance(obj, RecordDescriptor):
                    self.packer.register(obj)
                else:
                    if not self.selector or self.selector.match(obj):
                        yield obj
        except EOFError:
            pass


def record_stream(sources: list[str], selector: str | None = None) -> Iterator[Record]:
    """Return a Record stream generator from the given Record sources.

    Exceptions in a Record source will be caught so the stream is not interrupted.
    """
    log.debug("Record stream with selector: %r", selector)
    for src in sources:
        # Inform user that we are reading from stdin
        if src in ("-", ""):
            print("[reading from stdin]", file=sys.stderr)

        # Initial value for reader, in case of exception message
        reader = "RecordReader"
        try:
            reader = RecordReader(src, selector=selector)
            yield from reader
            reader.close()
        except IOError as e:
            log.exception("%s(%r): %s", reader, src, e)  # noqa: TRY401
        except KeyboardInterrupt:
            raise
        except Exception as e:
            log.warning("Exception in %r for %r: %s -- skipping to next reader", reader, src, aRepr.repr(e))
            continue


class PathTemplateWriter:
    """Write records to a path on disk, path can be a template string.

    This allows for archiving records on disk based on timestamp for example.

    Default template string is:

        '{name}-{record._generated:%Y%m%dT%H}.records.gz'

    Available template fields:

    `name` defaults to "records", but can be overridden in the initializer.
    `record` is the record object
    `ts` is record._generated

    If the destination path already exists it will rename the existing file using the current datetime.
    """

    DEFAULT_TEMPLATE = "{name}-{record._generated:%Y%m%dT%H}.records.gz"

    def __init__(self, path_template: str | None = None, name: str | None = None):
        self.path_template = path_template or self.DEFAULT_TEMPLATE
        self.name = name or "records"
        self.current_path = None
        self.writer = None
        self.stream = None

    def rotate_existing_file(self, path: Path) -> None:
        if path.exists():
            now = datetime.datetime.now(datetime.timezone.utc)
            src = path.resolve()

            src_dir = src.parent
            src_fname = src.name

            # stamp will be part of new filename to denote rotation stamp
            stamp = f"{now:%Y%m%dT%H%M%S}"

            # Use "records.gz" as the extension if we have this naming convention
            if src_fname.endswith(".records.gz"):
                fname, _ = src_fname.rsplit(".records.gz", 1)
                ext = "records.gz"
            else:
                fname, ext = src_fname.rsplit(".", 1)

            # insert the rotation stamp into the new filename.
            dst = src_dir.joinpath(f"{fname}.{stamp}.{ext}")
            log.info("RENAME %r -> %r", src, dst)
            src.rename(dst)

    def record_stream_for_path(self, path: str) -> AbstractWriter:
        if self.current_path != path:
            self.current_path = path
            log.info("Writing records to %r", path)
            pathobj = Path(path)
            self.rotate_existing_file(pathobj)
            dst_dir = pathobj.parent
            if not dst_dir.exists():
                dst_dir.mkdir(parents=True)
            rs = RecordWriter(pathobj)
            self.close()
            self.writer = rs
        return self.writer

    def write(self, record: Record) -> None:
        ts = record._generated or datetime.datetime.now(datetime.timezone.utc)
        path = self.path_template.format(name=self.name, record=record, ts=ts)
        rs = self.record_stream_for_path(path)
        rs.write(record)
        rs.fp.flush()

    def close(self) -> None:
        if self.writer:
            self.writer.close()


class RecordArchiver(PathTemplateWriter):
    """RecordWriter that writes/archives records to a path with YYYY/mm/dd."""

    def __init__(self, archive_path: str, path_template: str | None = None, name: str | None = None):
        path_template = path_template or self.DEFAULT_TEMPLATE
        template = str(Path(archive_path) / "{ts:%Y/%m/%d}" / path_template)
        PathTemplateWriter.__init__(self, path_template=template, name=name)


class RecordFieldRewriter:
    """Rewrite records using a new RecordDescriptor for chosen fields and/or excluded or new record fields."""

    def __init__(
        self, fields: list[str] | None = None, exclude: list[str] | None = None, expression: str | None = None
    ):
        self.fields = fields or []
        self.exclude = exclude or []
        self.expression = compile(expression, "<string>", "exec") if expression else None

        self.record_descriptor_for_fields = lru_cache(256)(self.record_descriptor_for_fields)

    def record_descriptor_for_fields(
        self,
        descriptor: RecordDescriptor,
        fields: list[str] | None = None,
        exclude: list[str] | None = None,
        new_fields: list[tuple[str, str]] | None = None,
    ) -> RecordDescriptor:
        if not fields and not exclude and not new_fields:
            return descriptor
        exclude = exclude or []
        desc_fields = []
        if fields:
            for fname in fields:
                if fname in exclude:
                    continue
                field = descriptor.fields.get(fname, None)
                if field:
                    desc_fields.append((field.typename, field.name))
        else:
            desc_fields = [(ftype, fname) for (ftype, fname) in descriptor.get_field_tuples() if fname not in exclude]
        if new_fields:
            desc_fields.extend(new_fields)
        return RecordDescriptor(descriptor.name, desc_fields)

    def rewrite(self, record: Record) -> Record:
        if not self.fields and not self.exclude and not self.expression:
            return record

        local_dict = {}
        new_fields = []
        if self.expression:
            exec(self.expression, record._asdict(), local_dict)
            # convert new variables to new record fields (field type is derived from value)
            new_fields = [(fieldtype_for_value(val, "string"), key) for key, val in local_dict.items()]

        RewriteRecord = self.record_descriptor_for_fields(
            record._desc, tuple(self.fields), tuple(self.exclude), tuple(new_fields)
        )
        # give new variables precendence
        return RewriteRecord.init_from_dict(ChainMap(local_dict, record._asdict()))
