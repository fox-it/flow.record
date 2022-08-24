import importlib
import io
import re
import os
import sys
import gzip
import struct
import logging
import keyword
import hashlib
import functools
import collections

try:
    # Python 2
    import urlparse
except ImportError:
    # Python 3
    import urllib.parse as urlparse
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
from operator import itemgetter as _itemgetter
from .whitelist import WHITELIST, WHITELIST_TREE
from .utils import to_str, to_native_str

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
from datetime import datetime
from itertools import zip_longest

class {name}(Record):
    _desc = desc
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


class RecordDescriptorError(Exception):
    pass


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

    def __init__(self, name, typename):
        if not is_valid_field_name(name, check_reserved=False):
            raise RecordDescriptorError("Invalid field name: {}".format(name))

        self.name = to_str(name)
        self.typename = to_str(typename)

        self.type = fieldtype(typename)

    def __repr__(self):
        return "<RecordField {} ({})>".format(self.name, self.typename)


class RecordFieldSet(list):
    pass


class RecordDescriptor:
    name = None
    fields = None
    recordType = None
    _desc_hash = None

    def __init__(self, name, fields=None):
        name = to_str(name)

        if isinstance(fields, RecordDescriptor):
            # Clone fields
            fields = fields.get_field_tuples()
        elif not fields:
            name, fields = parse_def(name)

        fields = list([(to_native_str(k), to_str(v)) for k, v in fields])

        contains_keyword = False
        for fieldtype, fieldname in fields:
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

        self.fields = OrderedDict([(n, RecordField(n, _type)) for _type, n in fields])
        all_fields = self.get_all_fields()
        self.name = name

        if not RE_VALID_RECORD_TYPE_NAME.match(name):
            raise RecordDescriptorError("Invalid record type name")

        args = ""
        init_code = ""
        unpack_code = ""

        if len(all_fields) >= 255 and not (sys.version_info >= (3, 7)) or contains_keyword:
            args = "*args, **kwargs"
            init_code = (
                "\t\tfor k, v in zip_longest(__self.__slots__, args):\n"
                "\t\t\tsetattr(__self, k, kwargs.get(k, v))\n"
                "\t\t_generated = __self._generated\n"
            )
            unpack_code = (
                "\t\tvalues = dict([(f, __cls._field_types[f]._unpack(kwargs.get(f, v)) "
                "if kwargs.get(f, v) is not None else None) for f, v in zip_longest(__cls.__slots__, args)])\n"
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

        init_code += "\t\t__self._generated = _generated or datetime.utcnow()\n\t\t__self._version = RECORD_VERSION"
        # Store the fieldtypes so we can enforce them in __setattr__()
        field_types = "{\n"
        for field in all_fields:
            field_types += "\t\t{field!r}: _field_{field}.type,\n".format(field=field)
        field_types += "\t}"

        code = RECORD_CLASS_TEMPLATE.format(
            name=name.replace("/", "_"),
            args=args,
            slots_tuple=tuple(all_fields.keys()),
            init_code=init_code,
            unpack_code=unpack_code,
            field_types=field_types,
        )

        code = code.replace("\t", "    ")
        c = compile(code, "<record code>", "exec")

        data = {
            "desc": self,
            "Record": Record,
            "OrderedDict": OrderedDict,
            "_itemgetter": _itemgetter,
            "_property": property,
            "RECORD_VERSION": RECORD_VERSION,
        }
        for field in all_fields.values():
            data["_field_{}".format(field.name)] = field

        exec(c, data)

        self.recordType = data[name.replace("/", "_")]

        self.identifier = (self.name, self.descriptor_hash)

    @staticmethod
    def get_required_fields():
        """
        Get required fields.

        Returns:
            OrderedDict

        """
        required_fields = OrderedDict([(k, RecordField(k, v)) for k, v in RESERVED_FIELDS.items()])
        return required_fields

    def get_all_fields(self):
        """
        Get all fields including required meta fields.

        Returns:
            OrderedDict

        """
        required_fields = self.get_required_fields()
        fields = self.fields.copy()
        fields.update(required_fields)
        return fields

    def getfields(self, typename):
        if isinstance(typename, DynamicFieldtypeModule):
            name = typename.gettypename()
        else:
            name = typename

        return RecordFieldSet(field for field in self.fields.values() if field.typename == name)

    def __call__(self, *args, **kwargs):
        return self.recordType(*args, **kwargs)

    def init_from_dict(self, rdict, raise_unknown=False):
        """Create a new Record initialized with key, value pairs from `rdict`.

        If `raise_unknown=True` then fields on `rdict` that are unknown to this
        RecordDescriptor will raise a TypeError exception due to initializing
        with unknown keyword arguments. (default: False)

        Returns:
            Record

        """

        if not raise_unknown:
            rdict = {k: v for k, v in rdict.items() if k in self.recordType.__slots__}
        return self.recordType(**rdict)

    def init_from_record(self, record, raise_unknown=False):
        """Create a new Record initialized with data from another `record`.

        If `raise_unknown=True` then fields on `record` that are unknown to this
        RecordDescriptor will raise a TypeError exception due to initializing
        with unknown keyword arguments. (default: False)

        Returns:
            Record

        """
        return self.init_from_dict(record._asdict(), raise_unknown=raise_unknown)

    def extend(self, fields):
        """Returns a new RecordDescriptor with the extended fields

        Returns:
            RecordDescriptor
        """
        new_fields = list(self.get_field_tuples()) + fields
        return RecordDescriptor(self.name, new_fields)

    def get_field_tuples(self):
        """Returns a tuple containing the (typename, name) tuples, eg:

        (('boolean', 'foo'), ('string', 'bar'))

        Returns:
            tuple
        """
        return tuple((self.fields[f].typename, self.fields[f].name) for f in self.fields)

    @staticmethod
    @functools.lru_cache(maxsize=256)
    def calc_descriptor_hash(name, fields):
        """Calculate and return the (cached) descriptor hash as a 32 bit integer.

        The descriptor hash is the first 4 bytes of the sha256sum of the descriptor name and field names and types.
        """
        h = hashlib.sha256(name.encode("utf-8"))
        for (typename, name) in fields:
            h.update(name.encode("utf-8"))
            h.update(typename.encode("utf-8"))
        return struct.unpack(">L", h.digest()[:4])[0]

    @property
    def descriptor_hash(self):
        """Returns the (cached) descriptor hash"""
        if not self._desc_hash:
            self._desc_hash = self.calc_descriptor_hash(self.name, self.get_field_tuples())
        return self._desc_hash

    def __hash__(self):
        return hash((self.name, self.get_field_tuples()))

    def __eq__(self, other):
        if isinstance(other, RecordDescriptor):
            return self.name == other.name and self.get_field_tuples() == other.get_field_tuples()
        return NotImplemented

    def __repr__(self):
        return "<RecordDescriptor {}, hash={:04x}>".format(self.name, self.descriptor_hash)

    def definition(self, reserved=True):
        """Return the RecordDescriptor as Python definition string.

        If `reserved` is True it will also return the reserved fields.
        """
        fields = []
        for ftype in self.get_all_fields().values():
            if not reserved and ftype.name.startswith("_"):
                continue
            fields.append('    ("{ftype.typename}", "{ftype.name}"),'.format(ftype=ftype))
        fields_str = "\n".join(fields)
        return 'RecordDescriptor("{}", [\n{}\n])'.format(self.name, fields_str)

    def base(self, **kwargs_sink):
        def wrapper(**kwargs):
            kwargs.update(kwargs_sink)
            return self.recordType(**kwargs)

        return wrapper

    def _pack(self):
        return self.name, [(field.typename, field.name) for field in self.fields.values()]

    @staticmethod
    def _unpack(name, fields):
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


def RecordAdapter(url, out, selector=None, clobber=True):
    url = url or ""
    url = str(url)

    # Guess adapter based on extension
    ext_to_adapter = {
        ".avro": "avro",
        ".json": "jsonfile",
    }
    _, ext = os.path.splitext(url)

    p = urlparse.urlparse(url, ext_to_adapter.get(ext, "stream"))

    if "+" in p.scheme:
        adapter, sub_adapter = p.scheme.split("+", 1)
    else:
        adapter = p.scheme
        sub_adapter = None

    mod = importlib.import_module("flow.record.adapter.{}".format(adapter))

    clsname = ("{}Writer" if out else "{}Reader").format(adapter.title())

    cls = getattr(mod, clsname)
    arg_dict = dict(urlparse.parse_qsl(p.query))
    cls_url = p.netloc + p.path
    if sub_adapter:
        cls_url = sub_adapter + "://" + cls_url

    if not out and selector:
        arg_dict["selector"] = selector

    if out:
        arg_dict["clobber"] = clobber

    log.debug("Creating {!r} for {!r} with args {!r}".format(cls, url, arg_dict))
    return cls(cls_url, **arg_dict)


def RecordReader(url=None, selector=None):
    return RecordAdapter(url, False, selector=selector)


def RecordWriter(url=None, clobber=True):
    return RecordAdapter(url, True, clobber=clobber)


def stream(src, dst):
    for r in src:
        dst.write(r)
    dst.flush()


def fieldtype(clspath):
    if clspath.endswith("[]"):
        origpath = clspath
        clspath = clspath[:-2]
        islist = True
    else:
        islist = False

    if clspath not in WHITELIST:
        raise AttributeError("Invalid field type: {}".format(clspath))

    p = clspath.rsplit(".", 1)
    module_path = "flow.record.fieldtypes"
    clsname = p.pop()
    if p:
        module_path += "." + p[0]

    mod = importlib.import_module(module_path)

    t = getattr(mod, clsname)

    if not issubclass(t, FieldType):
        raise AttributeError("Field type does not derive from FieldType")

    if islist:
        listtype = type(origpath, mod.typedlist.__bases__, dict(mod.typedlist.__dict__))
        listtype.__type__ = t
        t = listtype

    return t


def extend_record(record, other_records, replace=False, name=None):
    """Extend `record` with fields and values from `other_records`.

    Duplicate fields are ignored in `other_records` unless `replace=True`.

    Args:
        record (Record): Initial Record we want to extend.
        other_records (List[Record]): List of Records we use for extending/replacing.
        replace (bool): if `True`, it will replace existing fields and values
            in `record` from fields and values from `other_records`. Last record always wins.
        name (str): rename the RecordDescriptor name to `name`. Otherwise, use name from
            initial `record`.
    """
    field_map = collections.OrderedDict((fname, ftype) for (ftype, fname) in record._desc.get_field_tuples())
    record_maps = [record._asdict()]
    for other in other_records:
        for (ftype, fname) in other._desc.get_field_tuples():
            if not replace and fname in field_map:
                continue
            field_map[fname] = ftype
        record_maps.append(other._asdict())
    field_tuples = [(ftype, fname) for (fname, ftype) in field_map.items()]
    ExtendedRecord = RecordDescriptor(name or record._desc.name, field_tuples)
    if replace:
        record_maps = record_maps[::-1]
    return ExtendedRecord.init_from_dict(collections.ChainMap(*record_maps))


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
