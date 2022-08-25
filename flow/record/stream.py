from __future__ import print_function

import os
import sys
import struct
import logging
import datetime
from functools import lru_cache
from collections import ChainMap

from .base import RecordDescriptor, RecordReader
from .packer import RecordPacker
from flow.record import RecordWriter
from flow.record.selector import make_selector
from flow.record.fieldtypes import fieldtype_for_value


log = logging.getLogger(__package__)

RECORDSTREAM_MAGIC = b"RECORDSTREAM\n"


def RecordOutput(fp):
    """Return a RecordPrinter if `fp` is a tty otherwise a RecordStreamWriter."""
    if hasattr(fp, "isatty") and fp.isatty():
        return RecordPrinter(fp)
    return RecordStreamWriter(fp)


class RecordPrinter:
    """Records are printed as textual representation (repr) to fp."""

    fp = None

    def __init__(self, fp, flush=True):
        self.fp = fp
        self.auto_flush = flush

    def write(self, obj):
        buf = repr(obj).encode() + b"\n"
        self.fp.write(buf)
        if self.auto_flush:
            self.flush()

    def flush(self):
        self.fp.flush()

    def close(self):
        pass


class RecordStreamWriter:
    """Records are written as binary (serialized) to fp."""

    fp = None
    packer = None

    def __init__(self, fp):
        self.fp = fp
        self.packer = RecordPacker()
        self.packer.on_descriptor.add_handler(self.on_new_descriptor)
        self.header_written = False

    def __del__(self):
        self.close()

    def on_new_descriptor(self, descriptor):
        self.write(descriptor)

    def close(self):
        if self.fp and self.fp != getattr(sys.stdout, "buffer", sys.stdout):
            self.fp.close()
            self.fp = None

    def flush(self):
        if not self.header_written:
            self.writeheader()

    def write(self, obj):
        if not self.header_written:
            self.writeheader()
        blob = self.packer.pack(obj)
        self.fp.write(struct.pack(">I", len(blob)))
        self.fp.write(blob)

    def writeheader(self):
        self.header_written = True
        self.write(RECORDSTREAM_MAGIC)


class RecordStreamReader:
    fp = None
    recordtype = None
    descs = None
    packer = None

    def __init__(self, fp, selector=None):
        self.fp = fp
        self.closed = False
        self.selector = make_selector(selector)
        self.packer = RecordPacker()
        self.readheader()

    def readheader(self):
        # Manually read the msgpack format to avoid unserializing invalid data
        # we read size (4) + msgpack type (2) + msgpack bytes (recordstream magic)
        header = self.fp.read(4 + 2 + len(RECORDSTREAM_MAGIC))
        if not header.endswith(RECORDSTREAM_MAGIC):
            raise IOError("Unknown file format, not a RecordStream")

    def read(self):
        d = self.fp.read(4)
        if len(d) != 4:
            raise EOFError()

        size = struct.unpack(">I", d)[0]
        d = self.fp.read(size)
        return self.packer.unpack(d)

    def close(self):
        self.closed = True

    def __iter__(self):
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


def record_stream(sources, selector=None):
    """Return a Record stream generator from the given Record sources.

    Exceptions in a Record source will be caught so the stream is not interrupted.
    """
    log.debug("Record stream with selector: {!r}".format(selector))
    for src in sources:
        # Inform user that we are reading from stdin
        if src in ("-", ""):
            print("[reading from stdin]", file=sys.stderr)

        # Initial value for reader, in case of exception message
        reader = "RecordReader"
        try:
            reader = RecordReader(src, selector=selector)
            for rec in reader:
                yield rec
            reader.close()
        except IOError as e:
            log.error("{}({!r}): {}".format(reader, src, e))
        except KeyboardInterrupt:
            raise
        except Exception as e:  # noqa: B902
            log.warning("Exception in {!r} for {!r}: {!r} -- skipping to next reader".format(reader, src, e))
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

    def __init__(self, path_template=None, name=None):
        self.path_template = path_template or self.DEFAULT_TEMPLATE
        self.name = name or "records"
        self.current_path = None
        self.writer = None
        self.stream = None

    def rotate_existing_file(self, path):
        if os.path.exists(path):
            now = datetime.datetime.utcnow()
            src = os.path.realpath(path)

            src_dir = os.path.dirname(src)
            src_fname = os.path.basename(src)

            # stamp will be part of new filename to denote rotation stamp
            stamp = "{now:%Y%m%dT%H%M%S}".format(now=now)

            # Use "records.gz" as the extension if we have this naming convention
            if src_fname.endswith(".records.gz"):
                fname, _ = src_fname.rsplit(".records.gz", 1)
                ext = "records.gz"
            else:
                fname, ext = os.path.splitext(src_fname)

            # insert the rotation stamp into the new filename.
            dst = os.path.join(src_dir, "{fname}.{stamp}.{ext}".format(**locals()))
            log.info("RENAME {!r} -> {!r}".format(src, dst))
            os.rename(src, dst)

    def record_stream_for_path(self, path):
        if self.current_path != path:
            self.current_path = path
            log.info("Writing records to {!r}".format(path))
            self.rotate_existing_file(path)
            dst_dir = os.path.dirname(path)
            if not os.path.exists(dst_dir):
                os.makedirs(dst_dir)
            rs = RecordWriter(path)
            self.close()
            self.writer = rs
        return self.writer

    def write(self, record):
        ts = record._generated or datetime.datetime.utcnow()
        path = self.path_template.format(name=self.name, record=record, ts=ts)
        rs = self.record_stream_for_path(path)
        rs.write(record)
        rs.fp.flush()

    def close(self):
        if self.writer:
            self.writer.close()


class RecordArchiver(PathTemplateWriter):
    """RecordWriter that writes/archives records to a path with YYYY/mm/dd."""

    def __init__(self, archive_path, path_template=None, name=None):
        path_template = path_template or self.DEFAULT_TEMPLATE
        template = os.path.join(str(archive_path), "{ts:%Y/%m/%d}", path_template)
        PathTemplateWriter.__init__(self, path_template=template, name=name)


class RecordFieldRewriter:
    """Rewrite records using a new RecordDescriptor for chosen fields and/or excluded or new record fields."""

    def __init__(self, fields=None, exclude=None, expression=None):
        self.fields = fields or []
        self.exclude = exclude or []
        self.expression = compile(expression, "<string>", "exec") if expression else None

    @lru_cache(maxsize=256)
    def record_descriptor_for_fields(self, descriptor, fields=None, exclude=None, new_fields=None):
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

    def rewrite(self, record):
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
