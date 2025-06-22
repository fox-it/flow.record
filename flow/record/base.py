from __future__ import annotations

import collections
import functools
import gzip
import hashlib
import importlib
import io
import keyword
import logging
import os
import re
import sys
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
from typing import (
    IO,
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
)
from urllib.parse import parse_qsl, urlparse

from flow.record.exceptions import RecordAdapterNotFound, RecordDescriptorError
from flow.record.utils import get_stdin, get_stdout

try:
    import lz4.frame as lz4

    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False
try:
    import bz2

    HAS_BZ2 = True
except ImportError:
    HAS_BZ2 = False
try:
    import zstandard as zstd

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

try:
    import fastavro as avro  # noqa

    HAS_AVRO = True
except ImportError:
    HAS_AVRO = False

from collections import OrderedDict

from flow.record.utils import to_str
from flow.record.whitelist import WHITELIST, WHITELIST_TREE

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping, Sequence

    from flow.record.adapter import AbstractReader, AbstractWriter

log = logging.getLogger(__package__)
_utcnow = functools.partial(datetime.now, timezone.utc)

RECORD_VERSION = 1
RESERVED_FIELDS = OrderedDict(
    [
        ("_source", "string"),
        ("_classification", "string"),
        ("_generated", "datetime"),
        # For compatibility reasons, always add new reserved fields BEFORE
        # the _version field, but AFTER the second to last field
        ("_version", "varint"),
    ]
)

# Compression Headers
GZIP_MAGIC = b"\x1f\x8b"
BZ2_MAGIC = b"BZh"
LZ4_MAGIC = b"\x04\x22\x4d\x18"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
AVRO_MAGIC = b"Obj"

RECORDSTREAM_MAGIC = b"RECORDSTREAM\n"
RECORDSTREAM_MAGIC_DEPTH = 4 + 2 + len(RECORDSTREAM_MAGIC)

RE_VALID_FIELD_NAME = re.compile(r"^_?[a-zA-Z][a-zA-Z0-9_]*$")
RE_VALID_RECORD_TYPE_NAME = re.compile("^[a-zA-Z][a-zA-Z0-9_]*(/[a-zA-Z][a-zA-Z0-9_]*)*$")

RECORD_CLASS_TEMPLATE = """
class {name}(Record):
    _desc = None
    _field_types = {field_types}

    __slots__ = {slots_tuple}

    def __init__(__self, {args}):
{init_code}

    @classmethod
    def _unpack(__cls, {args}):
{unpack_code}
"""


if env_excluded_fields := os.environ.get("FLOW_RECORD_IGNORE"):
    IGNORE_FIELDS_FOR_COMPARISON = set(env_excluded_fields.split(","))
else:
    IGNORE_FIELDS_FOR_COMPARISON = set()


def set_ignored_fields_for_comparison(ignored_fields: Iterator[str]) -> None:
    """Can be used to update the IGNORE_FIELDS_FOR_COMPARISON from outside the flow.record package scope"""
    global IGNORE_FIELDS_FOR_COMPARISON
    IGNORE_FIELDS_FOR_COMPARISON = set(ignored_fields)


@contextmanager
def ignore_fields_for_comparison(ignored_fields: Iterator[str]) -> Iterator[None]:
    """Context manager to temporarily ignore fields for comparison."""
    original_ignored_fields = IGNORE_FIELDS_FOR_COMPARISON
    try:
        set_ignored_fields_for_comparison(ignored_fields)
        yield
    finally:
        set_ignored_fields_for_comparison(original_ignored_fields)


class FieldType:
    def _typename(self) -> None:
        t = type(self)
        t.__module__.split(".fieldtypes.")[1] + "." + t.__name__

    @classmethod
    def default(cls) -> None:
        """Return the default value for the field in the Record template."""
        return None  # noqa: RET501

    @classmethod
    def _unpack(cls, data: Any) -> Any:
        return data


class Record:
    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Record):
            return False

        return self._pack(excluded_fields=IGNORE_FIELDS_FOR_COMPARISON) == other._pack(
            excluded_fields=IGNORE_FIELDS_FOR_COMPARISON
        )

    def _pack(self, unversioned: bool = False, excluded_fields: list | None = None) -> tuple[tuple[str, int], tuple]:
        values = []
        for k in self.__slots__:
            v = getattr(self, k)
            v = v._pack() if isinstance(v, FieldType) else v

            if excluded_fields and k in excluded_fields:
                continue

            # Skip version field if requested (only for compatibility reasons)
            if unversioned and k == "_version" and v == 1:
                continue

            values.append(v)

        return self._desc.identifier, tuple(values)

    def _packdict(self) -> dict[str, Any]:
        return {
            k: v._pack() if isinstance(v, FieldType) else v for k, v in ((k, getattr(self, k)) for k in self.__slots__)
        }

    def _asdict(self, fields: list[str] | None = None, exclude: list[str] | None = None) -> dict[str, Any]:
        exclude = exclude or []
        if fields:
            return OrderedDict((k, getattr(self, k)) for k in fields if k in self.__slots__ and k not in exclude)
        return OrderedDict((k, getattr(self, k)) for k in self.__slots__ if k not in exclude)

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any: ...

    def __setattr__(self, k: str, v: Any) -> None:
        """Enforce setting the fields to their respective types."""
        # NOTE: This is a HOT code path
        field_type = self._field_types.get(k)
        if v is not None and k in self.__slots__ and field_type and not isinstance(v, field_type):
            v = field_type(v)
        super().__setattr__(k, v)

    def _replace(self, **kwds) -> Record:
        result = self.__class__(*map(kwds.pop, self.__slots__, (getattr(self, k) for k in self.__slots__)))
        if kwds:
            raise ValueError(f"Got unexpected field names: {list(kwds)!r}")
        return result

    def __hash__(self) -> int:
        desc_identifier, values = self._pack(excluded_fields=IGNORE_FIELDS_FOR_COMPARISON)
        if not any(isinstance(value, list) for value in values):
            return hash((desc_identifier, values))

        # Lists have to be converted to tuples to be able to hash them
        record_values = []
        for value in values:
            if not isinstance(value, list):
                record_values.append(value)
                continue
            list_values = []
            for list_value in value:
                if isinstance(list_value, dict):
                    # List values that are dicts must be converted to tuples
                    dict_as_tuple = tuple(list_value.items())
                    list_values.append(dict_as_tuple)
                else:
                    list_values.append(list_value)
            record_values.append(tuple(list_values))

        return hash((desc_identifier, tuple(record_values)))

    def __repr__(self) -> str:
        return "<{} {}>".format(self._desc.name, " ".join(f"{k}={getattr(self, k)!r}" for k in self._desc.fields))


class GroupedRecord(Record):
    """
    GroupedRecord acts like a normal Record, but can contain multiple records.

    See it as a flat Record view on top of multiple Records.
    If two Records have the same fieldname, the first one will prevail.
    """

    def __init__(self, name: str, records: list[Record | GroupedRecord]):
        super().__init__()
        self.name = to_str(name)
        self.records = []
        self.descriptors = []
        self.flat_fields = []

        # to avoid recursion in __setattr__ and __getattr__
        self.__dict__["fieldname_to_record"] = OrderedDict()

        for rec in records:
            if isinstance(rec, GroupedRecord):
                for r in rec.records:
                    self.records.append(r)
                    self.descriptors.append(r._desc)
            else:
                self.records.append(rec)
                self.descriptors.append(rec._desc)

            all_fields = rec._desc.get_all_fields()
            required_fields = rec._desc.get_required_fields()
            for field in all_fields.values():
                fname = field.name
                if fname in self.fieldname_to_record:
                    continue
                self.fieldname_to_record[fname] = rec
                if fname not in required_fields:
                    self.flat_fields.append(field)
        # Flat descriptor to maintain compatibility with Record

        self._desc = RecordDescriptor(self.name, [(f.typename, f.name) for f in self.flat_fields])

        # _field_types to maintain compatibility with RecordDescriptor
        self._field_types = self._desc.recordType._field_types

    def get_record_by_type(self, type_name: str) -> Record | None:
        """
        Get record in a GroupedRecord by type_name.

        Args:
            type_name (str): The record type name (for example wq/meta).

        Returns:
            None or the record

        """
        for record in self.records:
            if record._desc.name == type_name:
                return record
        return None

    def _asdict(self, fields: list[str] | None = None, exclude: list[str] | None = None) -> dict[str, Any]:
        exclude = exclude or []
        keys = self.fieldname_to_record.keys()
        if fields:
            return OrderedDict((k, getattr(self, k)) for k in fields if k in keys and k not in exclude)
        return OrderedDict((k, getattr(self, k)) for k in keys if k not in exclude)

    def __repr__(self) -> str:
        return f"<{self.name} {self.records}>"

    def __setattr__(self, attr: str, val: Any) -> None:
        if attr in getattr(self, "fieldname_to_record", {}):
            x = self.fieldname_to_record.get(attr)
            return setattr(x, attr, val)
        return object.__setattr__(self, attr, val)

    def __getattr__(self, attr: str) -> Any:
        x = self.__dict__.get("fieldname_to_record", {}).get(attr)
        if x:
            return getattr(x, attr)
        raise AttributeError(attr)

    def _pack(self) -> tuple[str, tuple]:
        return (
            self.name,
            tuple(record._pack() for record in self.records),
        )

    def _replace(self, **kwds) -> GroupedRecord:
        new_records = [
            record.__class__(*map(kwds.pop, record.__slots__, (getattr(self, k) for k in record.__slots__)))
            for record in self.records
        ]
        if kwds:
            raise ValueError(f"Got unexpected field names: {list(kwds)!r}")
        return GroupedRecord(self.name, new_records)


def is_valid_field_name(name: str, check_reserved: bool = True) -> bool:
    if check_reserved:
        if name in RESERVED_FIELDS:
            return False
    else:
        if name in RESERVED_FIELDS:
            return True

    if name.startswith("_"):
        return False

    return RE_VALID_FIELD_NAME.match(name)


def parse_def(definition: str) -> tuple[str, list[tuple[str, str]]]:
    warnings.warn("parse_def() is deprecated", DeprecationWarning, stacklevel=2)
    record_type = None
    fields = []
    for line in definition.split("\n"):
        line = line.strip()

        if not line:
            continue

        if not record_type:
            record_type = line
        else:
            _type, name = re.split(r"\s+", line.rstrip(";"))

            fields.append((_type, name))

    return record_type, fields


class RecordField:
    name = None
    typename = None
    type = None

    def __init__(self, name: str, typename: str):
        if not is_valid_field_name(name, check_reserved=False):
            raise RecordDescriptorError(f"Invalid field name: {name}")

        self.name = to_str(name)
        self.typename = to_str(typename)

        self.type = fieldtype(typename)

    def __repr__(self):
        return f"<RecordField {self.name} ({self.typename})>"


class RecordFieldSet(list):
    pass


@functools.lru_cache(maxsize=4096)
def _generate_record_class(name: str, fields: tuple[tuple[str, str]]) -> type:
    """Generate a record class

    Args:
        name: The name of the Record class.
        fields: A tuple of (fieldtype, fieldname) tuples.

    Returns:
        Record class
    """

    contains_keyword = False
    for _, fieldname in fields:
        if not is_valid_field_name(fieldname):
            raise RecordDescriptorError(f"Field '{fieldname}' is an invalid or reserved field name.")

        # Reserved Python keywords are allowed as field names, but at a cost.
        # When a Python keyword is used as a field name, you can't use it as a kwarg anymore
        # You'll be forced to either use *args or a expanding a dict to kwargs to initialize a record
        # E.g. Record('from_value', 'and_value') or Record(**{'from': 1, 'and': 2})
        # You'll also only be able to get or set reserved attributes using getattr or setattr.
        # Record initialization will also be slower, due to a different (slower) implementation
        # that is compatible with this method of initializing records.
        if keyword.iskeyword(fieldname):
            contains_keyword = True

    all_fields = OrderedDict([(n, RecordField(n, _type)) for _type, n in fields])
    all_fields.update(RecordDescriptor.get_required_fields())

    if not RE_VALID_RECORD_TYPE_NAME.match(name):
        raise RecordDescriptorError("Invalid record type name")

    name = name.replace("/", "_")
    args = ""
    init_code = ""
    unpack_code = ""

    if (len(all_fields) >= 255 and not (sys.version_info >= (3, 7))) or contains_keyword:
        args = "*args, **kwargs"
        init_code = (
            "\t\tfor k, v in _zip_longest(__self.__slots__, args):\n"
            "\t\t\tsetattr(__self, k, kwargs.get(k, v))\n"
            "\t\t_generated = __self._generated\n"
        )
        unpack_code = (
            "\t\tvalues = dict([(f, __cls._field_types[f]._unpack(kwargs.get(f, v)) "
            "if kwargs.get(f, v) is not None else None) for f, v in _zip_longest(__cls.__slots__, args)])\n"
            "\t\treturn __cls(**values)"
        )
    else:
        args = ", ".join([f"{k}=None" for k in all_fields])
        unpack_code = "\t\treturn __cls(\n"
        for field in all_fields.values():
            if field.type.default == FieldType.default:
                default = FieldType.default()
            else:
                default = f"_field_{field.name}.type.default()"
            init_code += f"\t\t__self.{field.name} = {field.name} if {field.name} is not None else {default}\n"
            unpack_code += (
                "\t\t\t{field} = _field_{field}.type._unpack({field}) " + "if {field} is not None else {default},\n"
            ).format(field=field.name, default=default)
        unpack_code += "\t\t)"

    init_code += "\t\t__self._generated = _generated or _utcnow()\n\t\t__self._version = RECORD_VERSION"
    # Store the fieldtypes so we can enforce them in __setattr__()
    field_types = "{\n"
    for field in all_fields:
        field_types += f"\t\t{field!r}: _field_{field}.type,\n"
    field_types += "\t}"

    code = RECORD_CLASS_TEMPLATE.format(
        name=name,
        args=args,
        slots_tuple=tuple(all_fields.keys()),
        init_code=init_code,
        unpack_code=unpack_code,
        field_types=field_types,
    ).replace("\t", "    ")

    _globals = {
        "Record": Record,
        "RECORD_VERSION": RECORD_VERSION,
        "_utcnow": _utcnow,
        "_zip_longest": zip_longest,
    }
    for field in all_fields.values():
        _globals[f"_field_{field.name}"] = field

    exec(code, _globals)

    return _globals[name]


class RecordDescriptor:
    """Record Descriptor class for defining a Record type and its fields."""

    name: str = None
    recordType: type = None
    _desc_hash: int = None
    _fields: Mapping[str, RecordField] = None
    _all_fields: Mapping[str, RecordField] = None
    _field_tuples: Sequence[tuple[str, str]] = None

    def __init__(self, name: str, fields: Sequence[tuple[str, str]] | None = None):
        if not name:
            raise RecordDescriptorError("Record name is required")

        # Marked for deprecation
        name = to_str(name)
        if isinstance(fields, RecordDescriptor):
            warnings.warn(
                "RecordDescriptor initialization with another RecordDescriptor is deprecated",
                DeprecationWarning,
                stacklevel=2,
            )
            # Clone fields
            fields = fields.get_field_tuples()
        elif fields is None:
            warnings.warn(
                "RecordDescriptor initialization by string only definition is deprecated",
                DeprecationWarning,
                stacklevel=2,
            )
            name, fields = parse_def(name)

        self.name = name
        self._field_tuples = tuple([(to_str(k), to_str(v)) for k, v in fields])
        self.recordType = _generate_record_class(name, self._field_tuples)
        self.recordType._desc = self

    @staticmethod
    @functools.lru_cache
    def get_required_fields() -> Mapping[str, RecordField]:
        """
        Get required fields mapping. eg:

        .. code-block:: text

            {
                "_source": RecordField("_source", "string"),
                "_classification": RecordField("_classification", "datetime"),
                "_generated": RecordField("_generated", "datetime"),
                "_version": RecordField("_version", "vaeint"),
            }

        Returns:
            Mapping of required fields
        """
        return OrderedDict([(k, RecordField(k, v)) for k, v in RESERVED_FIELDS.items()])

    @property
    def fields(self) -> Mapping[str, RecordField]:
        """
        Get fields mapping (without required fields). eg:

        .. code-block:: text

            {
                "foo": RecordField("foo", "string"),
                "bar": RecordField("bar", "varint"),
            }

        Returns:
            Mapping of Record fields
        """
        if self._fields is None:
            self._fields = OrderedDict([(n, RecordField(n, _type)) for _type, n in self._field_tuples])
        return self._fields

    def get_all_fields(self) -> Mapping[str, RecordField]:
        """
        Get all fields including required meta fields. eg:

        .. code-block:: text

            {
                "ts": RecordField("ts", "datetime"),
                "foo": RecordField("foo", "string"),
                "bar": RecordField("bar", "varint"),
                "_source": RecordField("_source", "string"),
                "_classification": RecordField("_classification", "datetime"),
                "_generated": RecordField("_generated", "datetime"),
                "_version": RecordField("_version", "varint"),
            }

        Returns:
            Mapping of all Record fields
        """
        if self._all_fields is None:
            self._all_fields = self.fields.copy()
            self._all_fields.update(self.get_required_fields())
        return self._all_fields

    def getfields(self, typename: str) -> RecordFieldSet:
        """Get fields of a given type.

        Args:
            typename: The typename of the fields to return. eg: "string" or "datetime"

        Returns:
            RecordFieldSet of fields with the given typename
        """
        name = typename.gettypename() if isinstance(typename, DynamicFieldtypeModule) else typename

        return RecordFieldSet(field for field in self.fields.values() if field.typename == name)

    def __call__(self, *args, **kwargs) -> Record:
        """Create a new Record initialized with ``args`` and ``kwargs``."""
        return self.recordType(*args, **kwargs)

    def init_from_dict(self, rdict: dict[str, Any], raise_unknown: bool = False) -> Record:
        """Create a new Record initialized with key, value pairs from ``rdict``.

        If ``raise_unknown=True`` then fields on ``rdict`` that are unknown to this
        RecordDescriptor will raise a TypeError exception due to initializing
        with unknown keyword arguments. (default: False)

        Returns:
            Record with data from ``rdict``
        """

        if not raise_unknown:
            rdict = {k: v for k, v in rdict.items() if k in self.recordType.__slots__}
        return self.recordType(**rdict)

    def init_from_record(self, record: Record, raise_unknown: bool = False) -> Record:
        """Create a new Record initialized with data from another ``record``.

        If ``raise_unknown=True`` then fields on ``record`` that are unknown to this
        RecordDescriptor will raise a TypeError exception due to initializing
        with unknown keyword arguments. (default: False)

        Returns:
            Record with data from ``record``
        """
        return self.init_from_dict(record._asdict(), raise_unknown=raise_unknown)

    def extend(self, fields: Sequence[tuple[str, str]]) -> RecordDescriptor:
        """Returns a new RecordDescriptor with the extended fields

        Returns:
            RecordDescriptor with extended fields
        """
        new_fields = list(self.get_field_tuples()) + fields
        return RecordDescriptor(self.name, new_fields)

    def get_field_tuples(self) -> tuple[tuple[str, str]]:
        """Returns a tuple containing the (typename, name) tuples, eg:

        .. code-block:: text

            (('boolean', 'foo'), ('string', 'bar'))

        Returns:
            Tuple of (typename, name) tuples
        """
        return self._field_tuples

    @staticmethod
    @functools.lru_cache(maxsize=256)
    def calc_descriptor_hash(name: str, fields: Sequence[tuple[str, str]]) -> int:
        """Calculate and return the (cached) descriptor hash as a 32 bit integer.

        The descriptor hash is the first 4 bytes of the sha256sum of the descriptor name and field names and types.
        """
        data = name + "".join(f"{n}{t}" for t, n in fields)
        return int.from_bytes(hashlib.sha256(data.encode()).digest()[:4], byteorder="big")

    @property
    def descriptor_hash(self) -> int:
        """Returns the (cached) descriptor hash"""
        if not self._desc_hash:
            self._desc_hash = self.calc_descriptor_hash(self.name, self._field_tuples)
        return self._desc_hash

    @property
    def identifier(self) -> tuple[str, int]:
        """Returns a tuple containing the descriptor name and hash"""
        return (self.name, self.descriptor_hash)

    def __hash__(self) -> int:
        return hash((self.name, self.get_field_tuples()))

    def __eq__(self, other: RecordDescriptor) -> bool:
        if isinstance(other, RecordDescriptor):
            return self.name == other.name and self.get_field_tuples() == other.get_field_tuples()
        return NotImplemented

    def __repr__(self) -> str:
        return f"<RecordDescriptor {self.name}, hash={self.descriptor_hash:04x}>"

    def definition(self, reserved: bool = True) -> str:
        """Return the RecordDescriptor as Python definition string.

        If ``reserved`` is True it will also return the reserved fields.

        Returns:
            Descriptor definition string
        """
        fields = []
        for ftype in self.get_all_fields().values():
            if not reserved and ftype.name.startswith("_"):
                continue
            fields.append(f'    ("{ftype.typename}", "{ftype.name}"),')
        fields_str = "\n".join(fields)
        return f'RecordDescriptor("{self.name}", [\n{fields_str}\n])'

    def base(self, **kwargs_sink) -> Callable[..., Record]:
        def wrapper(**kwargs) -> Record:
            kwargs.update(kwargs_sink)
            return self.recordType(**kwargs)

        return wrapper

    def _pack(self) -> tuple[str, tuple[tuple[str, str]]]:
        return (self.name, self._field_tuples)

    @staticmethod
    def _unpack(name: str, fields: tuple[tuple[str, str]]) -> RecordDescriptor:
        return RecordDescriptor(name, fields)


def DynamicDescriptor(name: str, fields: list[str]) -> RecordDescriptor:
    return RecordDescriptor(name, [("dynamic", field) for field in fields])


def open_stream(fp: BinaryIO, mode: str) -> BinaryIO:
    if "w" in mode:
        return fp
    if not hasattr(fp, "peek"):
        fp = io.BufferedReader(fp)

    # We peek into the file at the maximum possible length we might need, which is the amount of bytes needed to
    # determine whether a stream is a RECORDSTREAM or not.
    peek_data = fp.peek(RECORDSTREAM_MAGIC_DEPTH)

    # If the data stream is compressed, we wrap the file pointer in a reader that can decompress accordingly.
    if peek_data[:2] == GZIP_MAGIC:
        fp = gzip.GzipFile(fileobj=fp, mode=mode)
    elif HAS_BZ2 and peek_data[:3] == BZ2_MAGIC:
        fp = bz2.BZ2File(fp, mode=mode)
    elif HAS_LZ4 and peek_data[:4] == LZ4_MAGIC:
        fp = lz4.open(fp, mode=mode)
    elif HAS_ZSTD and peek_data[:4] == ZSTD_MAGIC:
        dctx = zstd.ZstdDecompressor()
        fp = dctx.stream_reader(fp)

    return fp


def find_adapter_for_stream(fp: BinaryIO) -> tuple[BinaryIO, str | None]:
    # We need to peek into the stream to be able to determine which adapter is needed. The fp given to this function
    # might already be an instance of the 'Peekable' class, but might also be a different file pointer, for example
    # a transparent decompressor. As calling peek() twice on the same peekable is not allowed, we wrap the fp into
    # a Peekable again, so that we are able to determine the correct adapter.
    if not hasattr(fp, "peek"):
        fp = io.BufferedReader(fp)

    peek_data = fp.peek(RECORDSTREAM_MAGIC_DEPTH)
    if HAS_AVRO and peek_data[:3] == AVRO_MAGIC:
        return fp, "avro"
    if RECORDSTREAM_MAGIC in peek_data[:RECORDSTREAM_MAGIC_DEPTH]:
        return fp, "stream"
    return fp, None


def open_path_or_stream(path: str | Path | BinaryIO, mode: str, clobber: bool = True) -> IO:
    if isinstance(path, Path):
        path = str(path)
    if isinstance(path, str):
        return open_path(path, mode, clobber)
    if isinstance(path, io.IOBase):
        return open_stream(path, mode)

    raise ValueError(f"Unsupported path type {path}")


def open_path(path: str, mode: str, clobber: bool = True) -> IO:
    """
    Open ``path`` using ``mode`` and returns a file object.

    It handles special cases if path is meant to be stdin or stdout.
    And also supports compression based on extension or file header of stream.

    Args:
        path: Filename or path to filename to open
        mode: Could be "r", "rb" to open file for reading, "w", "wb" for writing
        clobber: Overwrite file if it already exists if ``clobber=True``, else raises IOError.

    """
    binary = "b" in mode
    fp = None
    if mode in ("w", "wb"):
        out = True
    elif mode in ("r", "rb"):
        out = False
    else:
        raise ValueError(f"mode string can only be 'r', 'rb', 'w', or 'wb', not {mode!r}")

    # check for stdin or stdout
    is_stdio = path in (None, "", "-")
    pathobj = Path(path)

    # check if output path exists
    if not is_stdio and not clobber and pathobj.exists() and out:
        raise IOError(f"Output file {path!r} already exists, and clobber=False")

    # check path extension for compression
    if path:
        if path.endswith(".gz"):
            fp = gzip.GzipFile(path, mode)
        elif path.endswith(".bz2"):
            if not HAS_BZ2:
                raise RuntimeError("bz2 python module not available")
            fp = bz2.BZ2File(path, mode)
        elif path.endswith(".lz4"):
            if not HAS_LZ4:
                raise RuntimeError("lz4 python module not available")
            fp = lz4.open(path, mode)
        elif path.endswith((".zstd", ".zst")):
            if not HAS_ZSTD:
                raise RuntimeError("zstandard python module not available")
            if not out:
                dctx = zstd.ZstdDecompressor()
                fp = dctx.stream_reader(pathobj.open("rb"))
            else:
                cctx = zstd.ZstdCompressor()
                fp = cctx.stream_writer(pathobj.open("wb"))

    # normal file or stdio for reading or writing
    if not fp:
        fp = (get_stdout(binary=binary) if out else get_stdin(binary=binary)) if is_stdio else pathobj.open(mode)
        # check if we are reading a compressed stream
        if not out and binary:
            fp = open_stream(fp, mode)
    return fp


def RecordAdapter(
    url: str | None = None,
    out: bool = False,
    selector: str | None = None,
    clobber: bool = True,
    fileobj: BinaryIO | None = None,
    **kwargs,
) -> AbstractWriter | AbstractReader:
    # Guess adapter based on extension
    ext_to_adapter = {
        ".avro": "avro",
        ".json": "jsonfile",
        ".jsonl": "jsonfile",
        ".csv": "csvfile",
    }
    cls_stream = None
    cls_url = None
    adapter = None

    # When a url is given, we interpret it to determine what kind of adapter we need. This piece of logic is always
    # necessary for the RecordWriter (as it does not currently support file-like objects), and only needed for
    # RecordReader if a url is provided.
    if out is True or url not in ("-", "", None):
        # Either stdout / stdin is given, or a path-like string.
        url = str(url or "")
        ext = Path(url).suffix

        adapter_scheme = ext_to_adapter.get(ext, "stream")
        if "://" not in url:
            url = f"{adapter_scheme}://{url}"
        p = urlparse(url, scheme=adapter_scheme)
        adapter, _, sub_adapter = p.scheme.partition("+")

        arg_dict = dict(parse_qsl(p.query))
        arg_dict.update(kwargs)

        cls_url = p.netloc + p.path
        if sub_adapter:
            cls_url = sub_adapter + "://" + cls_url
    if out is False:
        if url in ("-", "", None) and fileobj is None:
            # For reading stdin, we cannot rely on an extension to know what sort of stream is incoming. Thus, we will
            # treat it as a 'fileobj', where we can peek into the stream and try to select the appropriate adapter.
            fileobj = get_stdin(binary=True)
        if fileobj is not None:
            # This record adapter has received a file-like object for record reading
            # We just need to find the right adapter by peeking into the first few bytes.

            # First, we open the stream. If the stream is compressed, open_stream will wrap it for us into a
            # decompressor.
            cls_stream = open_stream(fileobj, "rb")

            # If a user did not provide a url, we have to peek into the stream to be able to determine the right adapter
            # based on magic bytes encountered in the first few bytes of the stream.
            if adapter is None:
                # If we could not infere an adapter from the url, we have a stream that will be transparently
                # decompressed but we still do not know what adapter to use. This requires a new peek into the
                # transparent stream. This peek will cause the stream pointer to be moved. Therefore,
                # find_adapter_for_stream returns both a BinaryIO-supportive object that can correctly read the adjusted
                # stream, and a string indicating the type of adapter to be used on said stream.
                cls_stream, adapter = find_adapter_for_stream(cls_stream)
                if adapter is None:
                    # As peek() can result in a larger buffer than requested, so we truncate it just to be sure
                    peek_data = cls_stream.peek(RECORDSTREAM_MAGIC_DEPTH)[:RECORDSTREAM_MAGIC_DEPTH]
                    if peek_data and peek_data.startswith(b"<"):
                        raise RecordAdapterNotFound(
                            f"Could not find a reader for input {peek_data!r}. Are you perhaps "
                            "entering record text, rather than a record stream? This can be fixed by using "
                            "'rdump -w -' to write a record stream to stdout."
                        )
                    raise RecordAdapterNotFound("Could not find adapter for file-like object")

            # Now that we found an adapter, we will fall back into the same code path as when a URL is given. As the url
            # parsing path copied kwargs into an arg_dict variable, we will do the same so we do not get a variable
            # referenced before assignment error.
            arg_dict = kwargs.copy()

    # Now that we know which adapter is needed, we import it.
    mod = importlib.import_module(f"flow.record.adapter.{adapter}")
    clsname = ("{}Writer" if out else "{}Reader").format(adapter.title())

    cls = getattr(mod, clsname)
    if not out and selector:
        arg_dict["selector"] = selector

    if out:
        arg_dict["clobber"] = clobber
    log.debug("Creating %r for %r with args %r", cls, url, arg_dict)
    if cls_stream is not None:
        return cls(cls_stream, **arg_dict)
    if fileobj is not None:
        return cls(fileobj, **arg_dict)
    return cls(cls_url, **arg_dict)


def RecordReader(
    url: str | None = None,
    selector: str | None = None,
    fileobj: BinaryIO | None = None,
    **kwargs,
) -> AbstractReader:
    return RecordAdapter(url=url, out=False, selector=selector, fileobj=fileobj, **kwargs)


def RecordWriter(url: str | None = None, clobber: bool = True, **kwargs) -> AbstractWriter:
    return RecordAdapter(url=url, out=True, clobber=clobber, **kwargs)


def stream(src: AbstractReader, dst: AbstractWriter) -> None:
    for r in src:
        dst.write(r)
    dst.flush()


@functools.lru_cache
def fieldtype(clspath: str) -> FieldType:
    """Return the FieldType class for the given field type class path.

    Args:
        clspath: class path of the field type. eg: ``uint32``, ``net.ipaddress``, ``string[]``

    Returns:
        The FieldType class.
    """
    base_module_path = "flow.record.fieldtypes"

    if clspath.endswith("[]"):
        origpath = clspath
        clspath = clspath[:-2]
        islist = True
    else:
        islist = False

    if clspath not in WHITELIST:
        raise AttributeError(f"Invalid field type: {clspath}")

    namespace, _, clsname = clspath.rpartition(".")
    module_path = f"{base_module_path}.{namespace}" if namespace else base_module_path
    mod = importlib.import_module(module_path)

    fieldtype_cls = getattr(mod, clsname)

    if islist:
        base_mod = importlib.import_module(base_module_path)
        listtype = type(origpath, base_mod.typedlist.__bases__, dict(base_mod.typedlist.__dict__))
        listtype.__type__, fieldtype_cls = fieldtype_cls, listtype

    if not issubclass(fieldtype_cls, FieldType):
        raise TypeError("Field type does not derive from FieldType")

    return fieldtype_cls


@functools.lru_cache(maxsize=4069)
def merge_record_descriptors(
    descriptors: tuple[RecordDescriptor], replace: bool = False, name: str | None = None
) -> RecordDescriptor:
    """Create a newly merged RecordDescriptor from a list of RecordDescriptors.
    This function uses a cache to avoid creating the same descriptor multiple times.

    Duplicate fields are ignored in ``descriptors`` unless ``replace=True``.

    Args:
        descriptors: Tuple of RecordDescriptors to merge.
        replace: if ``True``, it will replace existing field names. Last descriptor always wins.
        name: rename the RecordDescriptor name to ``name``. Otherwise, use name from first descriptor.

    Returns:
        Merged RecordDescriptor
    """
    field_map = collections.OrderedDict()
    for desc in descriptors:
        for ftype, fname in desc.get_field_tuples():
            if not replace and fname in field_map:
                continue
            field_map[fname] = ftype
    if name is None and descriptors:
        name = descriptors[0].name
    return RecordDescriptor(name, zip(field_map.values(), field_map.keys()))


def extend_record(
    record: Record, other_records: list[Record], replace: bool = False, name: str | None = None
) -> Record:
    """Extend ``record`` with fields and values from ``other_records``.

    Duplicate fields are ignored in ``other_records`` unless ``replace=True``.

    Args:
        record: Initial Record to extend.
        other_records: List of Records to use for extending/replacing.
        replace: if ``True``, it will replace existing fields and values
            in ``record`` from fields and values from ``other_records``. Last record always wins.
        name: rename the RecordDescriptor name to ``name``. Otherwise, use name from
            initial ``record``.

    Returns:
        Extended Record
    """
    records = (record, *other_records)
    descriptors = tuple(rec._desc for rec in records)
    ExtendedRecord = merge_record_descriptors(descriptors, replace, name)
    kv_maps = tuple(rec._asdict() for rec in records)
    if replace:
        kv_maps = kv_maps[::-1]
    return ExtendedRecord.init_from_dict(collections.ChainMap(*kv_maps))


@functools.lru_cache(maxsize=4096)
def normalize_fieldname(field_name: str) -> str:
    """Returns a normalized version of ``field_name``.

    Some (field) names are not allowed in flow.record, while they can be allowed in other formats.
    This normalizes the name so it can still be used in flow.record.
    Reserved field_names are not normalized.

    .. code-block:: text

        >>> normalize_fieldname("my-variable-name-with-dashes")
        'my_variable_name_with_dashes'
        >>> normalize_fieldname("_my_name_starting_with_underscore")
        'x__my_name_starting_with_underscore'
        >>> normalize_fieldname("1337")
        'x_1337'
        >>> normalize_fieldname("my name with spaces")
        'my_name_with_spaces'
        >>> normalize_fieldname("my name (with) parentheses")
        'my_name__with__parentheses'
        >>> normalize_fieldname("_generated")
        '_generated'
    """

    if field_name not in RESERVED_FIELDS:
        field_name = re.sub(r"[- ()]", "_", field_name)
        # prepend `n_` if field_name is empty or starts with underscore or digit
        if len(field_name) == 0 or field_name.startswith("_") or field_name[0].isdecimal():
            field_name = "x_" + field_name
    return field_name


class DynamicFieldtypeModule:
    def __init__(self, path: str = ""):
        self.path = path

    def __getattr__(self, path: str) -> DynamicFieldtypeModule:
        path = (self.path + "." if self.path else "") + path

        obj = WHITELIST_TREE
        for p in path.split("."):
            if p not in obj:
                raise AttributeError(f"Invalid field type: {path}")
            obj = obj[p]

        return DynamicFieldtypeModule(path)

    def gettypename(self) -> str | None:
        if fieldtype(self.path):
            return self.path
        return None

    def __call__(self, *args, **kwargs) -> Any:
        t = fieldtype(self.path)

        return t(*args, **kwargs)


net = DynamicFieldtypeModule("net")
dynamic_fieldtype = DynamicFieldtypeModule()

TimestampRecord = RecordDescriptor(
    "record/timestamp",
    [
        ("datetime", "ts"),
        ("string", "ts_description"),
    ],
)


def iter_timestamped_records(record: Record) -> Iterator[Record]:
    """Yields timestamped annotated records for each ``datetime`` fieldtype in ``record``.
    If ``record`` does not have any ``datetime`` fields the original record is returned.

    Args:
        record: Record to add timestamp fields for.

    Yields:
        Record annotated with ``ts`` and ``ts_description`` fields for each ``datetime`` fieldtype.
    """

    # get all ``datetime`` fields. (excluding _generated).
    dt_fields = record._desc.getfields("datetime")
    if not dt_fields:
        yield record
        return

    # yield a new record for each ``datetime`` field assigned as ``ts``.
    record_name = record._desc.name
    for field in dt_fields:
        ts_record = TimestampRecord(getattr(record, field.name), field.name)
        # we extend ``ts_record`` with original ``record`` so TSRecord info goes first.
        record = extend_record(ts_record, [record], name=record_name)
        yield record
