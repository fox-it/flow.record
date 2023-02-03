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
from datetime import datetime
from itertools import zip_longest
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlparse

from .exceptions import RecordDescriptorError

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

from collections import OrderedDict

from .utils import to_native_str, to_str
from .whitelist import WHITELIST, WHITELIST_TREE

log = logging.getLogger(__package__)

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

RE_VALID_FIELD_NAME = re.compile(r"^_?[a-zA-Z][a-zA-Z0-9_]*(?:\[\])?$")
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


class Peekable:
    """Wrapper class for adding .peek() to a file object."""

    def __init__(self, fd):
        self.fd = fd
        self.buffer = None

    def peek(self, size):
        if self.buffer is not None:
            raise BufferError("Only 1 peek allowed")
        data = self.fd.read(size)
        self.buffer = io.BytesIO(data)
        return data

    def read(self, size=None):
        data = b""
        if self.buffer is None:
            data = self.fd.read(size)
        else:
            data = self.buffer.read(size)
            if len(data) < size:
                data += self.fd.read(size - len(data))
                self.buffer = None
        return data

    def close(self):
        self.buffer = None
        self.fd.close()
        self.fd = None


class FieldType:
    def _typename(self):
        t = type(self)
        t.__module__.split(".fieldtypes.")[1] + "." + t.__name__

    @classmethod
    def default(cls):
        """Return the default value for the field in the Record template."""
        return None

    @classmethod
    def _unpack(cls, data):
        return data


class Record:
    __slots__ = ()

    def __eq__(self, other):
        if not isinstance(other, Record):
            return False
        return self._pack() == other._pack()

    def _pack(self, unversioned=False):
        values = []
        for k in self.__slots__:
            v = getattr(self, k)
            v = v._pack() if isinstance(v, FieldType) else v

            # Skip version field if requested (only for compatibility reasons)
            if unversioned and k == "_version" and v == 1:
                continue
            else:
                values.append(v)

        return self._desc.identifier, tuple(values)

    def _packdict(self):
        return dict(
            (k, v._pack() if isinstance(v, FieldType) else v)
            for k, v in ((k, getattr(self, k)) for k in self.__slots__)
        )

    def _asdict(self, fields=None, exclude=None):
        exclude = exclude or []
        if fields:
            return OrderedDict((k, getattr(self, k)) for k in fields if k in self.__slots__ and k not in exclude)
        return OrderedDict((k, getattr(self, k)) for k in self.__slots__ if k not in exclude)

    def __setattr__(self, k, v):
        """Enforce setting the fields to their respective types."""
        # NOTE: This is a HOT code path
        field_type = self._field_types.get(k)
        if v is not None and k in self.__slots__ and field_type:
            if not isinstance(v, field_type):
                v = field_type(v)
        super().__setattr__(k, v)

    def _replace(self, **kwds):
        result = self.__class__(*map(kwds.pop, self.__slots__, (getattr(self, k) for k in self.__slots__)))
        if kwds:
            raise ValueError("Got unexpected field names: {kwds!r}".format(kwds=list(kwds)))
        return result

    def __repr__(self):
        return "<{} {}>".format(
            self._desc.name, " ".join("{}={!r}".format(k, getattr(self, k)) for k in self._desc.fields)
        )


class GroupedRecord(Record):
    """
    GroupedRecord acts like a normal Record, but can contain multiple records.

    See it as a flat Record view on top of multiple Records.
    If two Records have the same fieldname, the first one will prevail.
    """

    def __init__(self, name, records):
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
        # flat descriptor to maintain compatibility with Record

        self._desc = RecordDescriptor(self.name, [(f.typename, f.name) for f in self.flat_fields])

    def get_record_by_type(self, type_name):
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

    def _asdict(self, fields=None, exclude=None):
        exclude = exclude or []
        keys = self.fieldname_to_record.keys()
        if fields:
            return OrderedDict((k, getattr(self, k)) for k in fields if k in keys and k not in exclude)
        return OrderedDict((k, getattr(self, k)) for k in keys if k not in exclude)

    def __repr__(self):
        return "<{} {}>".format(self.name, self.records)

    def __setattr__(self, attr, val):
        if attr in getattr(self, "fieldname_to_record", {}):
            x = self.fieldname_to_record.get(attr)
            return setattr(x, attr, val)
        return object.__setattr__(self, attr, val)

    def __getattr__(self, attr):
        x = self.__dict__.get("fieldname_to_record", {}).get(attr)
        if x:
            return getattr(x, attr)
        raise AttributeError(attr)

    def _pack(self):
        return (
            self.name,
            tuple(record._pack() for record in self.records),
        )

    def _replace(self, **kwds):
        new_records = []
        for record in self.records:
            new_records.append(
                record.__class__(*map(kwds.pop, record.__slots__, (getattr(self, k) for k in record.__slots__)))
            )
        if kwds:
            raise ValueError("Got unexpected field names: {kwds!r}".format(kwds=list(kwds)))
        return GroupedRecord(self.name, new_records)


def is_valid_field_name(name, check_reserved=True):
    if check_reserved:
        if name in RESERVED_FIELDS:
            return False
    else:
        if name in RESERVED_FIELDS:
            return True

    if name.startswith("_"):
        return False

    if not RE_VALID_FIELD_NAME.match(name):
        return False

    return True


def parse_def(definition):
    warnings.warn("parse_def() is deprecated", DeprecationWarning)
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
            raise RecordDescriptorError("Invalid field name: {}".format(name))

        self.name = to_str(name)
        self.typename = to_str(typename)

        self.type = fieldtype(typename)

    def __repr__(self):
        return "<RecordField {} ({})>".format(self.name, self.typename)


class RecordFieldSet(list):
    pass


@functools.lru_cache(maxsize=4096)
def _generate_record_class(name: str, fields: Tuple[Tuple[str, str]]) -> type:
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
            raise RecordDescriptorError("Field '{}' is an invalid or reserved field name.".format(fieldname))

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

    if len(all_fields) >= 255 and not (sys.version_info >= (3, 7)) or contains_keyword:
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
        args = ", ".join(["{}=None".format(k) for k in all_fields])
        unpack_code = "\t\treturn __cls(\n"
        for field in all_fields.values():
            if field.type.default == FieldType.default:
                default = FieldType.default()
            else:
                default = "_field_{field.name}.type.default()".format(field=field)
            init_code += "\t\t__self.{field} = {field} if {field} is not None else {default}\n".format(
                field=field.name, default=default
            )
            unpack_code += (
                "\t\t\t{field} = _field_{field}.type._unpack({field}) " + "if {field} is not None else {default},\n"
            ).format(field=field.name, default=default)
        unpack_code += "\t\t)"

    init_code += "\t\t__self._generated = _generated or _utcnow()\n\t\t__self._version = RECORD_VERSION"
    # Store the fieldtypes so we can enforce them in __setattr__()
    field_types = "{\n"
    for field in all_fields:
        field_types += "\t\t{field!r}: _field_{field}.type,\n".format(field=field)
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
        "_utcnow": datetime.utcnow,
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
    _field_tuples: Sequence[Tuple[str, str]] = None

    def __init__(self, name: str, fields: Optional[Sequence[Tuple[str, str]]] = None):
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
        self._field_tuples = tuple([(to_native_str(k), to_str(v)) for k, v in fields])
        self.recordType = _generate_record_class(name, self._field_tuples)
        self.recordType._desc = self

    @staticmethod
    @functools.lru_cache()
    def get_required_fields() -> Mapping[str, RecordField]:
        """
        Get required fields mapping. eg:

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

        {
            "ts": RecordField("ts", "datetime"),
            "foo": RecordField("foo", "string"),
            "bar": RecordField("bar", "varint"),
            "_source": RecordField("_source", "string"),
            "_classification": RecordField("_classification", "datetime"),
            "_generated": RecordField("_generated", "datetime"),
            "_version": RecordField("_version", "vaeint"),
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
        if isinstance(typename, DynamicFieldtypeModule):
            name = typename.gettypename()
        else:
            name = typename

        return RecordFieldSet(field for field in self.fields.values() if field.typename == name)

    def __call__(self, *args, **kwargs) -> Record:
        """Create a new Record initialized with `args` and `kwargs`."""
        return self.recordType(*args, **kwargs)

    def init_from_dict(self, rdict: Dict[str, Any], raise_unknown=False) -> Record:
        """Create a new Record initialized with key, value pairs from `rdict`.

        If `raise_unknown=True` then fields on `rdict` that are unknown to this
        RecordDescriptor will raise a TypeError exception due to initializing
        with unknown keyword arguments. (default: False)

        Returns:
            Record with data from `rdict`
        """

        if not raise_unknown:
            rdict = {k: v for k, v in rdict.items() if k in self.recordType.__slots__}
        return self.recordType(**rdict)

    def init_from_record(self, record: Record, raise_unknown=False) -> Record:
        """Create a new Record initialized with data from another `record`.

        If `raise_unknown=True` then fields on `record` that are unknown to this
        RecordDescriptor will raise a TypeError exception due to initializing
        with unknown keyword arguments. (default: False)

        Returns:
            Record with data from `record`
        """
        return self.init_from_dict(record._asdict(), raise_unknown=raise_unknown)

    def extend(self, fields: Sequence[Tuple[str, str]]) -> RecordDescriptor:
        """Returns a new RecordDescriptor with the extended fields

        Returns:
            RecordDescriptor with extended fields
        """
        new_fields = list(self.get_field_tuples()) + fields
        return RecordDescriptor(self.name, new_fields)

    def get_field_tuples(self) -> Tuple[Tuple[str, str]]:
        """Returns a tuple containing the (typename, name) tuples, eg:

        (('boolean', 'foo'), ('string', 'bar'))

        Returns:
            Tuple of (typename, name) tuples
        """
        return self._field_tuples

    @staticmethod
    @functools.lru_cache(maxsize=256)
    def calc_descriptor_hash(name, fields: Sequence[Tuple[str, str]]) -> int:
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
    def identifier(self) -> Tuple[str, int]:
        """Returns a tuple containing the descriptor name and hash"""
        return (self.name, self.descriptor_hash)

    def __hash__(self) -> int:
        return hash((self.name, self.get_field_tuples()))

    def __eq__(self, other: RecordDescriptor) -> bool:
        if isinstance(other, RecordDescriptor):
            return self.name == other.name and self.get_field_tuples() == other.get_field_tuples()
        return NotImplemented

    def __repr__(self) -> str:
        return "<RecordDescriptor {}, hash={:04x}>".format(self.name, self.descriptor_hash)

    def definition(self, reserved: bool = True) -> str:
        """Return the RecordDescriptor as Python definition string.

        If `reserved` is True it will also return the reserved fields.

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

    def base(self, **kwargs_sink):
        def wrapper(**kwargs):
            kwargs.update(kwargs_sink)
            return self.recordType(**kwargs)

        return wrapper

    def _pack(self) -> Tuple[str, Tuple[Tuple[str, str]]]:
        return (self.name, self._field_tuples)

    @staticmethod
    def _unpack(name, fields: Tuple[Tuple[str, str]]) -> RecordDescriptor:
        return RecordDescriptor(name, fields)


def DynamicDescriptor(name, fields):
    return RecordDescriptor(name, [("dynamic", field) for field in fields])


def open_path(path, mode, clobber=True):
    """
    Open `path` using `mode` and returns a file object.

    It handles special cases if path is meant to be stdin or stdout.
    And also supports compression based on extension or file header of stream.

    Args:
        path (str): Filename or path to filename to open
        mode (str): Could be "r", "rb" to open file for reading, "w", "wb" for writing
        clobber (bool): Overwrite file if it already exists if `clobber=True`, else raises IOError.

    """
    binary = "b" in mode
    fp = None
    if mode in ("w", "wb"):
        out = True
    elif mode in ("r", "rb"):
        out = False
    else:
        raise ValueError("mode string can only be 'r', 'rb', 'w', or 'wb', not {!r}".format(mode))

    # check for stdin or stdout
    is_stdio = path in (None, "", "-")

    # check if output path exists
    if not is_stdio and not clobber and os.path.exists(path) and out:
        raise IOError("Output file {!r} already exists, and clobber=False".format(path))

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
                fp = dctx.stream_reader(open(path, "rb"))
            else:
                cctx = zstd.ZstdCompressor()
                fp = cctx.stream_writer(open(path, "wb"))

    # normal file or stdio for reading or writing
    if not fp:
        if is_stdio:
            if binary:
                fp = getattr(sys.stdout, "buffer", sys.stdout) if out else getattr(sys.stdin, "buffer", sys.stdin)
            else:
                fp = sys.stdout if out else sys.stdin
        else:
            fp = io.open(path, mode)
        # check if we are reading a compressed stream
        if not out and binary:
            if not hasattr(fp, "peek"):
                fp = Peekable(fp)
            peek_data = fp.peek(4)
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


def RecordAdapter(url, out, selector=None, clobber=True, **kwargs):
    url = str(url or "")

    # Guess adapter based on extension
    ext_to_adapter = {
        ".avro": "avro",
        ".json": "jsonfile",
        ".jsonl": "jsonfile",
        ".csv": "csvfile",
    }
    _, ext = os.path.splitext(url)

    adapter_scheme = ext_to_adapter.get(ext, "stream")
    if "://" not in url:
        url = f"{adapter_scheme}://{url}"

    p = urlparse(url, scheme=adapter_scheme)
    adapter, _, sub_adapter = p.scheme.partition("+")

    mod = importlib.import_module("flow.record.adapter.{}".format(adapter))

    clsname = ("{}Writer" if out else "{}Reader").format(adapter.title())

    cls = getattr(mod, clsname)
    arg_dict = dict(parse_qsl(p.query))
    arg_dict.update(kwargs)
    cls_url = p.netloc + p.path
    if sub_adapter:
        cls_url = sub_adapter + "://" + cls_url

    if not out and selector:
        arg_dict["selector"] = selector

    if out:
        arg_dict["clobber"] = clobber

    log.debug("Creating {!r} for {!r} with args {!r}".format(cls, url, arg_dict))
    return cls(cls_url, **arg_dict)


def RecordReader(url=None, selector=None, **kwargs):
    return RecordAdapter(url, False, selector=selector, **kwargs)


def RecordWriter(url=None, clobber=True, **kwargs):
    return RecordAdapter(url, True, clobber=clobber, **kwargs)


def stream(src, dst):
    for r in src:
        dst.write(r)
    dst.flush()


@functools.lru_cache()
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
        raise AttributeError("Invalid field type: {}".format(clspath))

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
    descriptors: Tuple[RecordDescriptor], replace: bool = False, name: Optional[str] = None
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
    record: Record, other_records: List[Record], replace: bool = False, name: Optional[str] = None
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


class DynamicFieldtypeModule:
    def __init__(self, path=""):
        self.path = path

    def __getattr__(self, path):
        path = (self.path + "." if self.path else "") + path

        obj = WHITELIST_TREE
        for p in path.split("."):
            if p not in obj:
                raise AttributeError("Invalid field type: {}".format(path))
            obj = obj[p]

        return DynamicFieldtypeModule(path)

    def gettypename(self):
        if fieldtype(self.path):
            return self.path

    def __call__(self, *args, **kwargs):
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
    """Yields timestamped annotated records for each `datetime` fieldtype in `record`.
    If `record` does not have any `datetime` fields the original record is returned.

    Args:
        record: Record to add timestamp fields for.

    Yields:
        Record annotated with `ts` and `ts_description` fields for each `datetime` fieldtype.
    """
    # get all `datetime` fields. (excluding _generated).
    dt_fields = record._desc.getfields("datetime")
    if not dt_fields:
        yield record
        return

    # yield a new record for each `datetime` field assigned as `ts`.
    record_name = record._desc.name
    for field in dt_fields:
        ts_record = TimestampRecord(getattr(record, field.name), field.name)
        # we extend `ts_record` with original `record` so TSRecord info goes first.
        record = extend_record(ts_record, [record], name=record_name)
        yield record
