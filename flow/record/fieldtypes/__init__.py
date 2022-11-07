import binascii
import math
import os
import pathlib
import re
from binascii import a2b_hex, b2a_hex
from datetime import datetime as _dt, timedelta
from posixpath import basename, dirname
from typing import Tuple

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse

import warnings

from flow.record.base import FieldType

RE_NORMALIZE_PATH = re.compile(r"[\\/]+")
NATIVE_UNICODE = isinstance("", str)

PATH_POSIX = 0
PATH_WINDOWS = 1

string_type = str
varint_type = int
bytes_type = bytes
float_type = float
path_type = pathlib.PurePath


def defang(value: str) -> str:
    """Defangs the value to make URLs or ip addresses unclickable"""
    value = re.sub("^http://", "hxxp://", value, flags=re.IGNORECASE)
    value = re.sub("^https://", "hxxps://", value, flags=re.IGNORECASE)
    value = re.sub("^ftp://", "fxp://", value, flags=re.IGNORECASE)
    value = re.sub("^file://", "fxle://", value, flags=re.IGNORECASE)
    value = re.sub("^ldap://", "ldxp://", value, flags=re.IGNORECASE)
    value = re.sub("^ldaps://", "ldxps://", value, flags=re.IGNORECASE)
    value = re.sub(r"(\w+)\.(\w+)($|/|:)", r"\1[.]\2\3", value, flags=re.IGNORECASE)
    value = re.sub(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", r"\1.\2.\3[.]\4", value, flags=re.IGNORECASE)
    return value


def fieldtype_for_value(value, default="string"):
    """Returns fieldtype name derived from the value. Returns `default` if it cannot be derived.

    Args:
        value: value to derive the fieldtype from

    Returns:
        str: the field type name or `default` if it cannot be derived

    Examples:
        >>> fieldtype_for_value("hello")
        "string"
        >>> fieldtype_for_value(1337)
        "varint"
        >>> fieldtype_for_value(object(), None)
        None
    """
    if isinstance(value, bytes_type):
        return "bytes"
    elif isinstance(value, string_type):
        return "string"
    elif isinstance(value, float_type):
        return "float"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, (varint_type, int)):
        return "varint"
    elif isinstance(value, _dt):
        return "datetime"
    elif isinstance(value, path_type):
        return "path"
    return default


class dynamic(FieldType):
    def __new__(cls, obj):
        if isinstance(obj, FieldType):
            # Already a flow field type
            return obj

        elif isinstance(obj, bytes_type):
            return bytes(obj)

        elif isinstance(obj, string_type):
            return string(obj)

        elif isinstance(obj, bool):
            # Must appear before int, because bool is a subclass of int
            return boolean(obj)

        elif isinstance(obj, (varint_type, int)):
            return varint(obj)

        elif isinstance(obj, _dt):
            return datetime(obj)

        elif isinstance(obj, (list, tuple)):
            return stringlist(obj)

        elif isinstance(obj, path_type):
            return path(obj)

        raise NotImplementedError("Unsupported type for dynamic fieldtype: {}".format(type(obj)))


class typedlist(list, FieldType):

    __type__ = None

    def __init__(self, values=None):
        if not values:
            values = []
        super(self.__class__, self).__init__(self._convert(values))

    def _convert(self, values):
        return [self.__type__(f) if not isinstance(f, self.__type__) else f for f in values]

    def _pack(self):
        result = []
        for f in self:
            if not isinstance(f, self.__type__):
                # Dont pack records already, it's the job of RecordPacker to pack record fields.
                # Otherwise unpacking will yield unexpected results (records that are not unpacked).
                if self.__type__ == record:
                    r = f
                else:
                    r = self.__type__(f)._pack()
                result.append(r)
            else:
                r = f._pack()
                result.append(r)
        return result

    @classmethod
    def _unpack(cls, data):
        data = map(cls.__type__._unpack, data)
        return cls(data)

    @classmethod
    def default(cls):
        """Override default so the field is always an empty list."""
        return cls()


class dictlist(list, FieldType):
    def _pack(self):
        return self


class stringlist(list, FieldType):
    def _pack(self):
        return self


class string(string_type, FieldType):
    def __new__(cls, value):
        if isinstance(value, bytes_type):
            value = cls._decode(value, "utf-8")
            if isinstance(value, bytes_type):
                # Still bytes, so decoding failed (Python 2)
                return bytes(value)
        return super().__new__(cls, value)

    def _pack(self):
        return self

    def __format__(self, spec):
        if spec == "defang":
            return defang(self)
        return str.__format__(self, spec)

    @classmethod
    def _decode(cls, data, encoding):
        """Decode a byte-string into a unicode-string.

        Python 3: When `data` contains invalid unicode characters a `UnicodeDecodeError` is raised.
        Python 2: When `data` contains invalid unicode characters the original byte-string is returned.
        """
        if NATIVE_UNICODE:
            # Raises exception on decode error
            return data.decode(encoding)
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            # Fallback to bytes (Python 2 only)
            preview = data[:16].encode("hex_codec") + (".." if len(data) > 16 else "")
            warnings.warn(
                "Got binary data in string field (hex: {}). Compatibility is not guaranteed.".format(preview),
                RuntimeWarning,
            )
            return data


# Alias for backwards compatibility
wstring = string


class bytes(bytes_type, FieldType):
    value = None

    def __init__(self, value):
        if not isinstance(value, bytes_type):
            raise TypeError("Value not of bytes type")
        self.value = value

    def _pack(self):
        return self.value

    def __repr__(self):
        return repr(self.value)

    def __format__(self, spec):
        if spec in ("hex", "x"):
            return self.hex()
        elif spec in ("HEX", "X"):
            return self.hex().upper()
        elif spec in ("#x"):
            return "0x" + self.hex()
        elif spec in ("#X"):
            return "0x" + self.hex().upper()
        return bytes_type.__format__(self, spec)


class datetime(_dt, FieldType):
    def __new__(cls, *args, **kwargs):
        if len(args) == 1 and not kwargs:
            arg = args[0]
            if isinstance(arg, bytes_type):
                arg = arg.decode("utf-8")
            if isinstance(arg, string_type):
                # I expect ISO 8601 format e.g. datetime.isformat()
                # When the microseconds part is 0, str(datetime) will not print the microsecond part (only seconds)
                # So we have to account for this.
                # String constructor is used for example in JsonRecordAdapter
                if "." in arg:
                    return cls.strptime(arg, "%Y-%m-%dT%H:%M:%S.%f")
                else:
                    return cls.strptime(arg, "%Y-%m-%dT%H:%M:%S")
            elif isinstance(arg, (int, float_type)):
                return cls.utcfromtimestamp(arg)
            elif isinstance(arg, (_dt,)):
                return _dt.__new__(
                    cls,
                    arg.year,
                    arg.month,
                    arg.day,
                    arg.hour,
                    arg.minute,
                    arg.second,
                    arg.microsecond,
                    arg.tzinfo,
                )

        return _dt.__new__(cls, *args, **kwargs)

    def __eq__(self, other):
        return self - other == timedelta(0)

    def _pack(self):
        return self

    def __repr__(self):
        result = str(self)
        return result


class varint(varint_type, FieldType):
    def _pack(self):
        return self


class float(float, FieldType):
    def _pack(self):
        return self


class uint16(int, FieldType):

    value = None

    def __init__(self, value):
        if value < 0 or value > 0xFFFF:
            raise ValueError("Value not within (0x0, 0xffff), got: {}".format(value))

        self.value = value

    def _pack(self):
        return self.value

    def __repr__(self):
        return str(self.value)


class uint32(int, FieldType):
    value = None

    def __init__(self, value):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError("Value not within (0x0, 0xffffffff), got {}".format(value))

        self.value = value

    def _pack(self):
        return self.value


class boolean(int, FieldType):
    value = None

    def __init__(self, value):
        if value < 0 or value > 1:
            raise ValueError("Value not a valid boolean value")

        self.value = bool(value)

    def _pack(self):
        return self.value

    def __str__(self):
        return str(self.value)

    def __repr__(self):
        return str(self.value)


def human_readable_size(x):
    # hybrid of http://stackoverflow.com/a/10171475/2595465
    #     with http://stackoverflow.com/a/5414105/2595465
    if x == 0:
        return "0"
    magnitude = int(math.log(abs(x), 10.24))
    if magnitude > 16:
        format_str = "%iP"
        # denominator_mag = 15
    else:
        float_fmt = "%2.1f" if magnitude % 3 == 1 else "%1.2f"
        illion = (magnitude + 1) // 3
        format_str = float_fmt + " " + [" ", "K", "M", "G", "T", "P"][illion]
    return (format_str % (x * 1.0 / (1024**illion))) + "B"


class filesize(varint):
    def __repr__(self):
        return human_readable_size(self)


class unix_file_mode(varint):
    def __repr__(self):
        return oct(self).rstrip("L")


class digest(FieldType):
    __md5 = __md5_bin = None
    __sha1 = __sha1_bin = None
    __sha256 = __sha256_bin = None

    def __init__(self, value=None, **kwargs):
        if isinstance(value, (tuple, list)):
            self.md5, self.sha1, self.sha256 = value
        elif isinstance(value, dict):
            self.md5 = value.get("md5", self.md5)
            self.sha1 = value.get("sha1", self.sha1)
            self.sha256 = value.get("sha256", self.sha256)

    @classmethod
    def default(cls):
        """Override default so the field is always a digest() instance."""
        return cls()

    def __repr__(self):
        return "(md5={d.md5}, sha1={d.sha1}, sha256={d.sha256})".format(d=self)

    @property
    def md5(self):
        return self.__md5

    @property
    def sha1(self):
        return self.__sha1

    @property
    def sha256(self):
        return self.__sha256

    @md5.setter
    def md5(self, val):
        if val is None:
            self.__md5 = self.__md5_bin = None
            return
        try:
            self.__md5_bin = a2b_hex(val)
            self.__md5 = val
            if len(self.__md5_bin) != 16:
                raise TypeError("Incorrect hash length")
        except binascii.Error as e:
            raise TypeError("Invalid MD5 value {!r}, {}".format(val, e))

    @sha1.setter
    def sha1(self, val):
        if val is None:
            self.__sha1 = self.__sha1_bin = None
            return
        try:
            self.__sha1_bin = a2b_hex(val)
            self.__sha1 = val
            if len(self.__sha1_bin) != 20:
                raise TypeError("Incorrect hash length")
        except binascii.Error as e:
            raise TypeError("Invalid SHA-1 value {!r}, {}".format(val, e))

    @sha256.setter
    def sha256(self, val):
        if val is None:
            self.__sha256 = self.__sha256_bin = None
            return
        try:
            self.__sha256_bin = a2b_hex(val)
            self.__sha256 = val
            if len(self.__sha256_bin) != 32:
                raise TypeError("Incorrect hash length")
        except binascii.Error as e:
            raise TypeError("Invalid SHA-256 value {!r}, {}".format(val, e))

    def _pack(self):
        return (
            self.__md5_bin,
            self.__sha1_bin,
            self.__sha256_bin,
        )

    @classmethod
    def _unpack(cls, data):
        value = (
            b2a_hex(data[0]).decode() if data[0] else None,
            b2a_hex(data[1]).decode() if data[1] else None,
            b2a_hex(data[2]).decode() if data[2] else None,
        )
        return cls(value)


class uri(string, FieldType):
    def __init__(self, value):
        self._parsed = urlparse.urlparse(value)

    @staticmethod
    def normalize(path):
        r"""Normalize Windows paths to posix.

        c:\windows\system32\cmd.exe -> c:/windows/system32/cmd.exe
        """
        warnings.warn(
            "Do not use class uri(...) for filesystem paths, use class path(...)",
            DeprecationWarning,
        )
        return RE_NORMALIZE_PATH.sub("/", path)

    @classmethod
    def from_windows(cls, path):
        """Initialize a uri instance from a windows path."""
        warnings.warn(
            "Do not use class uri(...) for filesystem paths, use class path(...)",
            DeprecationWarning,
        )
        return cls(uri.normalize(path))

    @property
    def scheme(self):
        return self._parsed.scheme

    @property
    def protocol(self):
        return self.scheme

    @property
    def netloc(self):
        return self._parsed.netloc

    @property
    def path(self):
        return self._parsed.path

    @property
    def params(self):
        return self._parsed.params

    @property
    def query(self):
        return self._parsed.query

    @property
    def args(self):
        return self.query

    @property
    def fragment(self):
        return self._parsed.fragment

    @property
    def username(self):
        return self._parsed.username

    @property
    def password(self):
        return self._parsed.password

    @property
    def hostname(self):
        return self._parsed.hostname

    @property
    def port(self):
        return self._parsed.port

    @property
    def filename(self):
        return basename(self.path)

    @property
    def dirname(self):
        return dirname(self.path)


class record(FieldType):
    def __new__(cls, record_value):
        return record_value

    def _pack(self):
        return self.value

    @classmethod
    def _unpack(cls, data):
        return data


class path(pathlib.PurePath, FieldType):
    def __new__(cls, *args):
        if cls is path:
            cls = windows_path if os.name == "nt" else posix_path
            if len(args) > 0:
                path_ = args[0]
                if isinstance(path_, pathlib.PureWindowsPath):
                    cls = windows_path
                elif isinstance(path_, pathlib.PurePosixPath):
                    cls = posix_path

        return cls._from_parts(args)

    def _pack(self):
        path_type = PATH_WINDOWS if self._flavour.sep == "\\" else PATH_POSIX
        return (str(self), path_type)

    @classmethod
    def _unpack(cls, data: Tuple[str, str]):
        path_, path_type = data
        if path_type == PATH_POSIX:
            return posix_path(path_)
        elif path_type == PATH_WINDOWS:
            return windows_path(path_)
        else:
            # Catch all: default to posix_path
            return posix_path(path_)

    @classmethod
    def from_posix(cls, path_: str):
        """Initialize a path instance from a posix path string using / as a separator."""
        return posix_path(path_)

    @classmethod
    def from_windows(cls, path_: str):
        """Initialize a path instance from a windows path string using \\ as a separator."""
        return windows_path(path_)


class posix_path(pathlib.PurePosixPath, path):
    pass


class windows_path(pathlib.PureWindowsPath, path):
    pass
