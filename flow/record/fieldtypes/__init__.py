from __future__ import annotations

import binascii
import math
import os
import pathlib
import re
import shlex
import sys
import warnings
from binascii import a2b_hex, b2a_hex
from datetime import datetime as _dt
from datetime import timezone
from posixpath import basename, dirname
from typing import Any
from urllib.parse import urlparse

try:
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:
        from backports.zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    HAS_ZONE_INFO = True
except ImportError:
    HAS_ZONE_INFO = False


from flow.record.base import FieldType, Record

RE_NORMALIZE_PATH = re.compile(r"[\\/]+")

UTC = timezone.utc

PY_311_OR_HIGHER = sys.version_info >= (3, 11, 0)
PY_312_OR_HIGHER = sys.version_info >= (3, 12, 0)
PY_313_OR_HIGHER = sys.version_info >= (3, 13, 0)

TYPE_POSIX = 0
TYPE_WINDOWS = 1

_bytes = bytes
_float = float


def flow_record_tz(*, default_tz: str = "UTC") -> ZoneInfo | UTC | None:
    """Return a ``ZoneInfo`` object based on the ``FLOW_RECORD_TZ`` environment variable.

    Args:
        default_tz: Default timezone if ``FLOW_RECORD_TZ`` is not set (default: UTC).

    Returns:
        None if ``FLOW_RECORD_TZ=NONE`` otherwise ``ZoneInfo(FLOW_RECORD_TZ)`` or ``UTC`` if ZoneInfo is not found.
    """

    tz = os.environ.get("FLOW_RECORD_TZ", default_tz)
    if tz.upper() == "NONE":
        return None

    if not HAS_ZONE_INFO:
        if tz != "UTC":
            warnings.warn(
                "Cannot use FLOW_RECORD_TZ due to missing zoneinfo module, defaulting to 'UTC'.", stacklevel=2
            )
        return UTC

    try:
        return ZoneInfo(tz)
    except ZoneInfoNotFoundError as exc:
        if tz != "UTC":
            warnings.warn(f"{exc!r}, falling back to timezone.utc", stacklevel=2)
        return UTC


# The environment variable ``FLOW_RECORD_TZ`` affects the display of datetime fields.
#
# The timezone to use when displaying datetime fields. By default this is UTC.
DISPLAY_TZINFO = flow_record_tz(default_tz="UTC")


def defang(value: str) -> str:
    """Defangs the value to make URLs or ip addresses unclickable"""
    value = re.sub("^http://", "hxxp://", value, flags=re.IGNORECASE)
    value = re.sub("^https://", "hxxps://", value, flags=re.IGNORECASE)
    value = re.sub("^ftp://", "fxp://", value, flags=re.IGNORECASE)
    value = re.sub("^file://", "fxle://", value, flags=re.IGNORECASE)
    value = re.sub("^ldap://", "ldxp://", value, flags=re.IGNORECASE)
    value = re.sub("^ldaps://", "ldxps://", value, flags=re.IGNORECASE)
    value = re.sub(r"(\w+)\.(\w+)($|/|:)", r"\1[.]\2\3", value, flags=re.IGNORECASE)
    return re.sub(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", r"\1.\2.\3[.]\4", value, flags=re.IGNORECASE)


def fieldtype_for_value(value: object, default: str = "string") -> str:
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
    if isinstance(value, _bytes):
        return "bytes"
    if isinstance(value, str):
        return "string"
    if isinstance(value, _float):
        return "float"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "varint"
    if isinstance(value, _dt):
        return "datetime"
    if isinstance(value, pathlib.PurePath):
        return "path"
    return default


class dynamic(FieldType):
    def __new__(cls, obj: object):
        if isinstance(obj, FieldType):
            # Already a flow field type
            return obj

        if isinstance(obj, _bytes):
            return bytes(obj)

        if isinstance(obj, str):
            return string(obj)

        if isinstance(obj, bool):
            # Must appear before int, because bool is a subclass of int
            return boolean(obj)

        if isinstance(obj, int):
            return varint(obj)

        if isinstance(obj, _float):
            return float(obj)

        if isinstance(obj, _dt):
            return datetime(obj)

        if isinstance(obj, (list, tuple)):
            return stringlist(obj)

        if isinstance(obj, pathlib.PurePath):
            return path(obj)

        raise NotImplementedError(f"Unsupported type for dynamic fieldtype: {type(obj)}")


class typedlist(list, FieldType):
    __type__ = None

    def __init__(self, values: list[Any] | None = None):
        if not values:
            values = []
        super(self.__class__, self).__init__(self._convert(values))

    def _convert(self, values: list[Any]) -> list[Any]:
        return [self.__type__(f) if not isinstance(f, self.__type__) else f for f in values]

    def _pack(self) -> list[Any]:
        result = []
        for f in self:
            if not isinstance(f, self.__type__):
                # Dont pack records already, it's the job of RecordPacker to pack record fields.
                # Otherwise unpacking will yield unexpected results (records that are not unpacked).
                r = f if self.__type__ == record else self.__type__(f)._pack()
                result.append(r)
            else:
                r = f._pack()
                result.append(r)
        return result

    @classmethod
    def _unpack(cls, data: Any) -> typedlist:
        data = map(cls.__type__._unpack, data)
        return cls(data)

    @classmethod
    def default(cls) -> typedlist:
        """Override default so the field is always an empty list."""
        return cls()


class dictlist(list, FieldType):
    def _pack(self) -> dictlist:
        return self


class stringlist(list, FieldType):
    def _pack(self) -> stringlist:
        return self


class string(str, FieldType):
    __slots__ = ()

    def __new__(cls, value: str | _bytes):
        if isinstance(value, _bytes):
            value = value.decode(errors="surrogateescape")
        return super().__new__(cls, value)

    def _pack(self) -> string:
        return self

    def __format__(self, spec: str) -> str:
        if spec == "defang":
            return defang(self)
        return str.__format__(self, spec)


# Alias for backwards compatibility
wstring = string


class bytes(_bytes, FieldType):
    def __new__(cls, value: _bytes):
        if not isinstance(value, _bytes):
            raise TypeError("Value not of bytes type")
        return super().__new__(cls, value)

    def _pack(self) -> _bytes:
        return self

    def __format__(self, spec: str) -> str:
        if spec in ("hex", "x"):
            return self.hex()
        if spec in ("HEX", "X"):
            return self.hex().upper()
        if spec == "#x":
            return "0x" + self.hex()
        if spec == "#X":
            return "0x" + self.hex().upper()
        return _bytes.__format__(self, spec)


class datetime(_dt, FieldType):
    def __new__(cls, *args, **kwargs):
        if len(args) == 1 and not kwargs:
            arg = args[0]
            if isinstance(arg, _bytes):
                arg = arg.decode(errors="surrogateescape")
            if isinstance(arg, str):
                # If we are on Python 3.11 or newer, we can use fromisoformat() to parse the string (fast path)
                #
                # Else we need to do some manual parsing to fix some issues with the string format:
                # - Python 3.10 and older do not support nanoseconds in fromisoformat()
                # - Python 3.10 and older do not support Z as timezone info in fromisoformat()
                # - Python 3.10 and older do not support +0200 as timezone info in fromisoformat()
                # - Python 3.10 and older requires "T" between date and time in fromisoformat()
                #
                # There are other incompatibilities, but we don't care about those for now.
                if not PY_311_OR_HIGHER:
                    # Convert Z to +00:00 so that fromisoformat() works correctly on Python 3.10 and older
                    if arg[-1] == "Z":
                        arg = arg[:-1] + "+00:00"

                    # Find timezone info after the date part. Possible formats, so we use the longest one:
                    #
                    # YYYYmmdd      length: 8
                    # YYYY-mm-dd    length: 10
                    tstr = arg
                    tzstr = ""
                    tzsearch = arg[10:]
                    if tzpos := tzsearch.find("+") + 1 or tzsearch.find("-") + 1:
                        tzstr = arg[10 + tzpos - 1 :]
                        tstr = arg[: 10 + tzpos - 1]

                    # Convert +0200 to +02:00 so that fromisoformat() works correctly on Python 3.10 and older
                    if len(tzstr) == 5 and tzstr[3] != ":":
                        tzstr = tzstr[:3] + ":" + tzstr[3:]

                    # Python 3.10 and older do not support nanoseconds in fromisoformat()
                    if microsecond_pos := arg.rfind(".") + 1:
                        microseconds = arg[microsecond_pos:]
                        tstr = arg[: microsecond_pos - 1]
                        if tzpos := (microseconds.find("+") + 1 or microseconds.find("-") + 1):
                            microseconds = microseconds[: tzpos - 1]
                        # Pad microseconds to 6 digits, truncate if longer
                        microseconds = microseconds.ljust(6, "0")[:6]
                        arg = tstr + "." + microseconds + tzstr
                    else:
                        arg = tstr + tzstr

                obj = cls.fromisoformat(arg)
            elif isinstance(arg, (int, _float)):
                obj = cls.fromtimestamp(arg, UTC)
            elif isinstance(arg, (_dt,)):
                tzinfo = arg.tzinfo or UTC
                obj = _dt.__new__(
                    cls,
                    arg.year,
                    arg.month,
                    arg.day,
                    arg.hour,
                    arg.minute,
                    arg.second,
                    arg.microsecond,
                    tzinfo,
                )
        else:
            obj = _dt.__new__(cls, *args, **kwargs)

        # Ensure we always return a timezone aware datetime. Treat naive datetimes as UTC
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=UTC)
        return obj

    def _pack(self) -> datetime:
        return self

    def __str__(self) -> str:
        return self.astimezone(DISPLAY_TZINFO).isoformat(" ") if DISPLAY_TZINFO else self.isoformat(" ")

    def __repr__(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return _dt.__hash__(self)


class varint(int, FieldType):
    def _pack(self) -> varint:
        return self


class float(_float, FieldType):
    def _pack(self) -> float:
        return self


class uint16(int, FieldType):
    value = None

    def __init__(self, value: int):
        if value < 0 or value > 0xFFFF:
            raise ValueError(f"Value not within (0x0, 0xffff), got: {value}")

        self.value = value

    def _pack(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return str(self.value)


class uint32(int, FieldType):
    value = None

    def __init__(self, value: int):
        if value < 0 or value > 0xFFFFFFFF:
            raise ValueError(f"Value not within (0x0, 0xffffffff), got {value}")

        self.value = value

    def _pack(self) -> int:
        return self.value


class boolean(int, FieldType):
    value = None

    def __init__(self, value: bool):
        if value < 0 or value > 1:
            raise ValueError("Value not a valid boolean value")

        self.value = bool(value)

    def _pack(self) -> bool:
        return self.value

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)


def human_readable_size(x: int) -> str:
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
    def __repr__(self) -> str:
        return human_readable_size(self)


class unix_file_mode(varint):
    def __repr__(self) -> str:
        return oct(self).rstrip("L")


class digest(FieldType):
    __md5 = __md5_bin = None
    __sha1 = __sha1_bin = None
    __sha256 = __sha256_bin = None

    def __init__(self, value: tuple[str, str, str] | list[str] | dict[str, str] | None = None, **kwargs):
        if isinstance(value, (tuple, list)):
            self.md5, self.sha1, self.sha256 = value
        elif isinstance(value, dict):
            self.md5 = value.get("md5", self.md5)
            self.sha1 = value.get("sha1", self.sha1)
            self.sha256 = value.get("sha256", self.sha256)

    @classmethod
    def default(cls) -> digest:
        """Override default so the field is always a digest() instance."""
        return cls()

    def __repr__(self) -> str:
        return f"(md5={self.md5}, sha1={self.sha1}, sha256={self.sha256})"

    @property
    def md5(self) -> str | None:
        return self.__md5

    @property
    def sha1(self) -> str | None:
        return self.__sha1

    @property
    def sha256(self) -> str | None:
        return self.__sha256

    @md5.setter
    def md5(self, val: str | None) -> None:
        if val is None:
            self.__md5 = self.__md5_bin = None
            return
        try:
            self.__md5_bin = a2b_hex(val)
            self.__md5 = val
            if len(self.__md5_bin) != 16:
                raise TypeError("Incorrect hash length")  # noqa: TRY301
        except (binascii.Error, TypeError) as e:
            raise TypeError(f"Invalid MD5 value {val!r}, {e}")

    @sha1.setter
    def sha1(self, val: str | None) -> None:
        if val is None:
            self.__sha1 = self.__sha1_bin = None
            return
        try:
            self.__sha1_bin = a2b_hex(val)
            self.__sha1 = val
            if len(self.__sha1_bin) != 20:
                raise TypeError("Incorrect hash length")  # noqa: TRY301
        except (binascii.Error, TypeError) as e:
            raise TypeError(f"Invalid SHA-1 value {val!r}, {e}")

    @sha256.setter
    def sha256(self, val: str | None) -> None:
        if val is None:
            self.__sha256 = self.__sha256_bin = None
            return
        try:
            self.__sha256_bin = a2b_hex(val)
            self.__sha256 = val
            if len(self.__sha256_bin) != 32:
                raise TypeError("Incorrect hash length")  # noqa: TRY301
        except (binascii.Error, TypeError) as e:
            raise TypeError(f"Invalid SHA-256 value {val!r}, {e}")

    def _pack(self) -> tuple[_bytes | None, _bytes | None, _bytes | None]:
        return (
            self.__md5_bin,
            self.__sha1_bin,
            self.__sha256_bin,
        )

    @classmethod
    def _unpack(cls, data: tuple[_bytes | None, _bytes | None, _bytes | None]) -> digest:
        value = (
            b2a_hex(data[0]).decode() if data[0] else None,
            b2a_hex(data[1]).decode() if data[1] else None,
            b2a_hex(data[2]).decode() if data[2] else None,
        )
        return cls(value)


class uri(string, FieldType):
    def __init__(self, value: str):
        self._parsed = urlparse(value)

    @staticmethod
    def normalize(path: str) -> str:
        r"""Normalize Windows paths to posix.

        c:\windows\system32\cmd.exe -> c:/windows/system32/cmd.exe
        """
        warnings.warn(
            "Do not use class uri(...) for filesystem paths, use class path(...)",
            DeprecationWarning,
            stacklevel=2,
        )
        return RE_NORMALIZE_PATH.sub("/", path)

    @classmethod
    def from_windows(cls, path: str) -> uri:
        """Initialize a uri instance from a windows path."""
        warnings.warn(
            "Do not use class uri(...) for filesystem paths, use class path(...)",
            DeprecationWarning,
            stacklevel=2,
        )
        return cls(uri.normalize(path))

    @property
    def scheme(self) -> str:
        return self._parsed.scheme

    @property
    def protocol(self) -> str:
        return self.scheme

    @property
    def netloc(self) -> str:
        return self._parsed.netloc

    @property
    def path(self) -> str:
        return self._parsed.path

    @property
    def params(self) -> str:
        return self._parsed.params

    @property
    def query(self) -> str:
        return self._parsed.query

    @property
    def args(self) -> str:
        return self.query

    @property
    def fragment(self) -> str:
        return self._parsed.fragment

    @property
    def username(self) -> str | None:
        return self._parsed.username

    @property
    def password(self) -> str | None:
        return self._parsed.password

    @property
    def hostname(self) -> str | None:
        return self._parsed.hostname

    @property
    def port(self) -> int | None:
        return self._parsed.port

    @property
    def filename(self) -> str:
        return basename(self.path)

    @property
    def dirname(self) -> str:
        return dirname(self.path)


class record(FieldType):
    def __new__(cls, record_value: Record):
        return record_value

    def _pack(self) -> Record:
        return self.value

    @classmethod
    def _unpack(cls, data: Record) -> Record:
        return data


def _is_posixlike_path(path: Any) -> bool:
    if isinstance(path, pathlib.PurePath):
        obj = getattr(path, "parser", None) or path._flavour
        return "\\" not in (obj.sep, obj.altsep)
    return False


def _is_windowslike_path(path: Any) -> bool:
    if isinstance(path, pathlib.PurePath):
        obj = getattr(path, "parser", None) or path._flavour
        return "\\" in (obj.sep, obj.altsep)
    return False


class path(pathlib.PurePath, FieldType):
    _empty_path = False

    def __new__(cls, *args):
        # This is modelled after pathlib.PurePath's __new__(), which means you
        # will never get an instance of path, only instances of either
        # posix_path or windows_path.
        if cls is path:
            # By default, path will behave differently on windows and posix
            # systems, similarly as pathlib.PurePath does.
            cls = windows_path if os.name == "nt" else posix_path

            # Try to determine the path behaviour based on the first path part
            # in args that has pathlib.PurePath traits.
            for path_part in args:
                if isinstance(path_part, pathlib.PureWindowsPath):
                    cls = windows_path
                    if not PY_312_OR_HIGHER:
                        # For Python < 3.12, the (string) representation of a
                        # pathlib.PureWindowsPath is not round trip equivalent if a path
                        # starts with a \ or / followed by a drive letter, e.g.: \C:\...
                        # Meaning:
                        #
                        # str(PureWindowsPath(r"\C:\WINDOWS/Temp")) !=
                        # str(PureWindowsPath(PureWindowsPath(r"\C:\WINDOWS/Temp"))),
                        #
                        # repr(PureWindowsPath(r"\C:\WINDOWS/Temp")) !=
                        # repr(PureWindowsPath(PureWindowsPath(r"\C:\WINDOWS/Temp"))),
                        #
                        # This would be the case though when using PurePosixPath instead.
                        #
                        # This construction works around that by converting all path parts
                        # to strings first.
                        args = tuple(str(arg) for arg in args)
                elif isinstance(path_part, pathlib.PurePosixPath):
                    cls = posix_path
                elif _is_windowslike_path(path_part):
                    # This handles any custom PurePath based implementations that have a windows
                    # like path separator (\).
                    cls = windows_path
                    if not PY_312_OR_HIGHER:
                        args = tuple(str(arg) for arg in args)
                elif _is_posixlike_path(path_part):
                    # This handles any custom PurePath based implementations that don't have a
                    # windows like path separator (\).
                    cls = posix_path
                else:
                    continue
                break

        obj = super().__new__(cls) if PY_312_OR_HIGHER else cls._from_parts(args)

        obj._empty_path = False
        if not args or args == ("",):
            obj._empty_path = True
        return obj

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return str(self) == other or self == self.__class__(other)
        if isinstance(other, self.__class__) and (self._empty_path or other._empty_path):
            return self._empty_path == other._empty_path
        return super().__eq__(other)

    def __str__(self) -> str:
        if self._empty_path:
            return ""
        return super().__str__()

    def __repr__(self) -> str:
        return repr(str(self))

    @property
    def parent(self) -> path:
        if self._empty_path:
            return self
        return super().parent

    def _pack(self) -> tuple[str, int]:
        path_type = TYPE_WINDOWS if isinstance(self, windows_path) else TYPE_POSIX
        return (str(self), path_type)

    @classmethod
    def _unpack(cls, data: tuple[str, str]) -> posix_path | windows_path:
        path_, path_type = data
        if path_type == TYPE_POSIX:
            return posix_path(path_)
        if path_type == TYPE_WINDOWS:
            return windows_path(path_)
        # Catch all: default to posix_path
        return posix_path(path_)

    @classmethod
    def from_posix(cls, path_: str) -> posix_path:
        """Initialize a path instance from a posix path string using / as a separator."""
        return posix_path(path_)

    @classmethod
    def from_windows(cls, path_: str) -> windows_path:
        """Initialize a path instance from a windows path string using \\ or / as a separator."""
        return windows_path(path_)


class posix_path(pathlib.PurePosixPath, path):
    pass


class windows_path(pathlib.PureWindowsPath, path):
    def __repr__(self) -> str:
        s = str(self)
        quote = "'"
        if "'" in s:
            if '"' in s:
                s = s.replace("'", "\\'")
            else:
                quote = '"'

        return f"{quote}{s}{quote}"


class command(FieldType):
    executable: path | None = None
    args: list[str] | None = None

    _path_type: type[path] = None
    _posix: bool

    def __new__(cls, value: str):
        if cls is not command:
            return super().__new__(cls)

        if not isinstance(value, str):
            raise TypeError(f"Expected a value of type 'str' not {type(value)}")

        # pre checking for windows like paths
        # This checks for windows like starts of a path:
        #   an '%' for an environment variable
        #   r'\\' for a UNC path
        #   the strip and check for ":" on the second line is for `<drive_letter>:`
        stripped_value = value.lstrip("\"'")
        windows = value.startswith((r"\\", "%")) or (len(stripped_value) >= 2 and stripped_value[1] == ":")

        cls = windows_command if windows else posix_command
        return super().__new__(cls)

    def __init__(self, value: str | tuple[str, tuple[str]] | None):
        if value is None:
            return

        if isinstance(value, str):
            self.executable, self.args = self._split(value)
            return

        executable, self.args = value
        self.executable = self._path_type(executable)
        self.args = list(self.args)

    def __repr__(self) -> str:
        return f"(executable={self.executable!r}, args={self.args})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, command):
            return self.executable == other.executable and self.args == other.args
        if isinstance(other, str):
            return self._join() == other
        if isinstance(other, (tuple, list)):
            return self.executable == other[0] and self.args == list(other[1:])

        return False

    def _split(self, value: str) -> tuple[str, list[str]]:
        executable, *args = shlex.split(value, posix=self._posix)
        executable = executable.strip("'\" ")

        return self._path_type(executable), args

    def _join(self) -> str:
        return shlex.join([str(self.executable), *self.args])

    def _pack(self) -> tuple[tuple[str, list], str]:
        command_type = TYPE_WINDOWS if isinstance(self, windows_command) else TYPE_POSIX
        if self.executable:
            _exec, _ = self.executable._pack()
            return ((_exec, self.args), command_type)
        return (None, command_type)

    @classmethod
    def _unpack(cls, data: tuple[tuple[str, tuple] | None, int]) -> command:
        _value, _type = data
        if _type == TYPE_WINDOWS:
            return windows_command(_value)

        return posix_command(_value)

    @classmethod
    def from_posix(cls, value: str) -> command:
        return posix_command(value)

    @classmethod
    def from_windows(cls, value: str) -> command:
        return windows_command(value)


class posix_command(command):
    _posix = True
    _path_type = posix_path


class windows_command(command):
    _posix = False
    _path_type = windows_path

    def _split(self, value: str) -> tuple[str, list[str]]:
        executable, args = super()._split(value)
        if args:
            args = [" ".join(args)]

        return executable, args

    def _join(self) -> str:
        arg = f" {self.args[0]}" if self.args else ""
        executable_str = str(self.executable)

        if " " in executable_str:
            return f"'{executable_str}'{arg}"

        return f"{executable_str}{arg}"
