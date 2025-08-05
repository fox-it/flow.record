from __future__ import annotations

import hashlib
import os
import pathlib
import posixpath
import types
from datetime import datetime, timedelta, timezone
from typing import Callable

import pytest

import flow.record.fieldtypes
from flow.record import RecordDescriptor, RecordReader, RecordWriter, fieldtypes
from flow.record.fieldtypes import (
    PY_312_OR_HIGHER,
    PY_313_OR_HIGHER,
    TYPE_POSIX,
    TYPE_WINDOWS,
    _is_posixlike_path,
    _is_windowslike_path,
    command,
    fieldtype_for_value,
    net,
    posix_command,
    posix_path,
    uri,
    windows_command,
    windows_path,
)
from flow.record.fieldtypes import datetime as dt

UTC = timezone.utc

INT64_MAX = (1 << 63) - 1
INT32_MAX = (1 << 31) - 1
INT16_MAX = (1 << 15) - 1

UINT128_MAX = (1 << 128) - 1
UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
UINT16_MAX = (1 << 16) - 1


def test_uint16() -> None:
    desc = RecordDescriptor(
        "test/uint16",
        [
            ("uint16", "value"),
        ],
    )

    # valid
    desc.recordType(0x0)
    desc.recordType(0x1)
    desc.recordType(UINT16_MAX)

    # invalid
    with pytest.raises(ValueError, match="Value not within"):
        desc.recordType(-1)

    with pytest.raises(ValueError, match="Value not within"):
        desc.recordType(UINT16_MAX + 1)

    with pytest.raises((ValueError, OverflowError)):
        desc.recordType(UINT128_MAX)


def test_uint32() -> None:
    TestRecord = RecordDescriptor(
        "test/uint32",
        [
            ("uint32", "value"),
        ],
    )

    # valid
    TestRecord(0x0)
    TestRecord(0x1)
    TestRecord(UINT16_MAX)
    TestRecord(UINT32_MAX)

    # invalid
    with pytest.raises(ValueError, match="Value not within"):
        TestRecord(-1)

    with pytest.raises(ValueError, match="Value not within"):
        TestRecord(UINT32_MAX + 1)

    with pytest.raises((ValueError, OverflowError)):
        TestRecord(UINT128_MAX)


def test_net_ipv4_address() -> None:
    TestRecord = RecordDescriptor(
        "test/net/ipv4/address",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )

    with pytest.deprecated_call():
        TestRecord("1.1.1.1")
        TestRecord("0.0.0.0")
        TestRecord("192.168.0.1")
        TestRecord("255.255.255.255")

        r = TestRecord("127.0.0.1")

    assert isinstance(r.ip, net.ipv4.Address)

    for invalid in ["1.1.1.256", "192.168.0.1/24", "a.b.c.d"]:
        with pytest.raises(Exception, match=r".*illegal IP address string.*"), pytest.deprecated_call():
            TestRecord(invalid)

    r = TestRecord()
    assert r.ip is None


def test_net_ipv4_subnet() -> None:
    TestRecord = RecordDescriptor(
        "test/net/ipv4/subnet",
        [
            ("net.ipv4.Subnet", "subnet"),
        ],
    )

    with pytest.deprecated_call():
        r = TestRecord("1.1.1.0/24")
    assert str(r.subnet) == "1.1.1.0/24"

    assert "1.1.1.1" in r.subnet
    assert "1.1.1.2" in r.subnet

    assert "1.1.2.1" not in r.subnet
    # assert "1.1.1.1/32" not in r.subnet

    with pytest.deprecated_call():
        r = TestRecord("0.0.0.0")
        r = TestRecord("192.168.0.1")
        r = TestRecord("255.255.255.255")

        r = TestRecord("127.0.0.1")

    for invalid in ["a.b.c.d", "foo", "bar", ""]:
        with pytest.raises(Exception, match=r".*illegal IP address string.*"), pytest.deprecated_call():
            TestRecord(invalid)

    for invalid in [1, 1.0, sum, {}, [], True]:
        with (
            pytest.raises(TypeError, match=r"Subnet\(\) argument 1 must be string, not .*"),
            pytest.deprecated_call(),
        ):
            TestRecord(invalid)

    with (
        pytest.raises(
            ValueError, match=r"Not a valid subnet '192\.168\.0\.106/28', did you mean '192\.168\.0\.96/28' ?"
        ),
        pytest.deprecated_call(),
    ):
        TestRecord("192.168.0.106/28")


def test_bytes() -> None:
    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("string", "url"),
            ("bytes", "body"),
        ],
    )

    r = TestRecord("url", b"some bytes")
    assert r.body == b"some bytes"

    with pytest.raises(TypeError, match="Value not of bytes type"):
        r = TestRecord("url", 1234)

    with pytest.raises(TypeError, match="Value not of bytes type"):
        r = TestRecord("url", "a string")

    b_array = bytes(bytearray(range(256)))
    body = b"HTTP/1.1 200 OK\r\n\r\n" + b_array
    r = TestRecord("http://www.fox-it.com", body)
    assert r
    assert r.url == "http://www.fox-it.com"
    assert r.body == b"HTTP/1.1 200 OK\r\n\r\n" + b_array

    # testcase when input are bytes
    r = TestRecord("http://www.fox-it.com", b"HTTP/1.1 500 Error\r\n\r\nError")
    assert r.body == b"HTTP/1.1 500 Error\r\n\r\nError"


def test_string() -> None:
    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("string", "name"),
        ],
    )

    r = TestRecord("Fox-IT")
    assert r.name == "Fox-IT"

    r = TestRecord("Rémy")
    assert r.name == "Rémy"

    # construct from 'bytes'
    r = TestRecord(b"R\xc3\xa9my")
    assert r.name == "Rémy"

    # construct from 'bytes' but with invalid unicode bytes
    r = TestRecord(b"R\xc3\xa9\xeamy")
    assert r.name == "Ré\udceamy"


def test_wstring() -> None:
    # Behaves the same as test/string, only available for backwards compatibility purposes
    TestRecord = RecordDescriptor(
        "test/wstring",
        [
            ("wstring", "name"),
        ],
    )

    r = TestRecord("Fox-IT")
    assert r.name == "Fox-IT"


def test_typedlist() -> None:
    TestRecord = RecordDescriptor(
        "test/typedlist",
        [
            ("string[]", "string_value"),
            ("uint32[]", "uint32_value"),
            ("uri[]", "uri_value"),
            ("net.ipaddress[]", "ip_value"),
        ],
    )

    r = TestRecord(["a", "b", "c"], [1, 2, 3], ["/etc/passwd", "/etc/shadow"], ["1.1.1.1", "8.8.8.8"])
    assert len(r.string_value) == 3
    assert len(r.uint32_value) == 3
    assert len(r.uri_value) == 2
    assert r.string_value[2] == "c"
    assert r.uint32_value[1] == 2
    assert all(isinstance(v, uri) for v in r.uri_value)
    assert r.uri_value[1].filename == "shadow"
    assert list(map(str, r.ip_value)) == ["1.1.1.1", "8.8.8.8"]

    r = TestRecord()
    assert r.string_value == []
    assert r.uint32_value == []
    assert r.uri_value == []
    assert r.ip_value == []

    with pytest.raises(ValueError, match="invalid literal for int"):
        r = TestRecord(uint32_value=["a", "b", "c"])


def test_stringlist() -> None:
    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("stringlist", "value"),
        ],
    )

    r = TestRecord(["a", "b", "c"])
    assert len(r.value) == 3
    assert r.value[2] == "c"

    r = TestRecord(["Rémy"])
    assert r.value[0]


def test_dictlist() -> None:
    TestRecord = RecordDescriptor(
        "test/dictlist",
        [
            ("dictlist", "hits"),
        ],
    )

    r = TestRecord([{"a": 1, "b": 2}, {"a": 3, "b": 4}])
    assert len(r.hits) == 2
    assert r.hits == [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    assert r.hits[0]["a"] == 1
    assert r.hits[0]["b"] == 2
    assert r.hits[1]["a"] == 3
    assert r.hits[1]["b"] == 4


def test_boolean() -> None:
    TestRecord = RecordDescriptor(
        "test/boolean",
        [
            ("boolean", "booltrue"),
            ("boolean", "boolfalse"),
        ],
    )

    r = TestRecord(True, False)
    assert bool(r.booltrue) is True
    assert bool(r.boolfalse) is False

    r = TestRecord(1, 0)
    assert bool(r.booltrue) is True
    assert bool(r.boolfalse) is False

    assert str(r.booltrue) == "True"
    assert str(r.boolfalse) == "False"

    assert repr(r.booltrue) == "True"
    assert repr(r.boolfalse) == "False"

    with pytest.raises(ValueError, match="Value not a valid boolean value"):
        r = TestRecord(2, -1)

    with pytest.raises(ValueError, match="invalid literal for int"):
        r = TestRecord("True", "False")


def test_float() -> None:
    TestRecord = RecordDescriptor(
        "test/float",
        [
            ("float", "value"),
        ],
    )

    # initialize via float
    r = TestRecord(1.3337)
    assert r.value == 1.3337

    # initialize via string
    r = TestRecord("1.3337")
    assert r.value == 1.3337

    # initialize via int
    r = TestRecord("1337")
    assert r.value == 1337.0

    # negative float
    r = TestRecord(-12345)
    assert r.value == -12345

    # invalid float
    with pytest.raises(ValueError, match="could not convert string to float"):
        r = TestRecord("abc")


def test_uri_type() -> None:
    TestRecord = RecordDescriptor(
        "test/uri",
        [
            ("uri", "path"),
        ],
    )

    r = TestRecord("http://www.google.com/a.bin")
    assert r.path.filename == "a.bin"
    assert r.path.dirname == "/"
    assert r.path.hostname == "www.google.com"
    assert r.path.protocol == "http"
    assert r.path.protocol == r.path.scheme
    assert r.path.path == "/a.bin"

    r = TestRecord("http://username:password@example.com/path/file.txt?query=1")
    assert r.path.filename == "file.txt"
    assert r.path.dirname == "/path"
    assert r.path.args == "query=1"
    assert r.path.username == "username"
    assert r.path.password == "password"
    assert r.path.protocol == "http"
    assert r.path.hostname == "example.com"

    with pytest.warns(
        DeprecationWarning, match=r"Do not use class uri\(...\) for filesystem paths, use class path\(...\)"
    ):
        r = TestRecord(uri.from_windows(r"c:\windows\program files\Fox-IT B.V\flow.exe"))
    assert r.path.filename == "flow.exe"

    r = TestRecord()
    with pytest.warns(
        DeprecationWarning, match=r"Do not use class uri\(...\) for filesystem paths, use class path\(...\)"
    ):
        r.path = uri.normalize(r"c:\Users\Fox-IT\Downloads\autoruns.exe")
    assert r.path.filename == "autoruns.exe"
    with pytest.warns(
        DeprecationWarning, match=r"Do not use class uri\(...\) for filesystem paths, use class path\(...\)"
    ):
        assert r.path.dirname == uri.normalize(r"\Users\Fox-IT\Downloads")
    assert r.path.dirname == "/Users/Fox-IT/Downloads"

    r = TestRecord()
    r.path = "/usr/local/bin/sshd"
    assert r.path.filename == "sshd"
    assert r.path.dirname == "/usr/local/bin"


def test_datetime() -> None:
    TestRecord = RecordDescriptor(
        "test/datetime",
        [
            ("datetime", "ts"),
        ],
    )

    now = datetime.now(UTC)
    r = TestRecord(now)
    assert r.ts == now

    r = TestRecord("2018-03-22T15:15:23")
    assert r.ts == datetime(2018, 3, 22, 15, 15, 23, tzinfo=UTC)

    r = TestRecord("2018-03-22T15:15:23.000000")
    assert r.ts == datetime(2018, 3, 22, 15, 15, 23, tzinfo=UTC)

    r = TestRecord("2018-03-22T15:15:23.123456")
    assert r.ts == datetime(2018, 3, 22, 15, 15, 23, 123456, tzinfo=UTC)

    dt = datetime(2018, 3, 22, 15, 15, 23, 123456, tzinfo=UTC)
    dt_str = dt.isoformat()
    r = TestRecord(dt_str)
    assert r.ts == dt

    r = TestRecord(1521731723)
    assert r.ts == datetime(2018, 3, 22, 15, 15, 23, tzinfo=UTC)

    r = TestRecord(1521731723.123456)
    assert r.ts == datetime(2018, 3, 22, 15, 15, 23, 123456, tzinfo=UTC)

    r = TestRecord("2018-03-22T15:15:23.123456")
    test = {r.ts: "Success"}
    assert test[r.ts] == "Success"


@pytest.mark.parametrize(
    ("value", "expected_dt"),
    [
        ("2023-12-31T13:37:01.123456Z", datetime(2023, 12, 31, 13, 37, 1, 123456, tzinfo=UTC)),
        ("2023-01-10T16:12:01+00:00", datetime(2023, 1, 10, 16, 12, 1, tzinfo=UTC)),
        ("2023-01-10T16:12:01", datetime(2023, 1, 10, 16, 12, 1, tzinfo=UTC)),
        ("2023-01-10T16:12:01Z", datetime(2023, 1, 10, 16, 12, 1, tzinfo=UTC)),
        ("2022-12-01T13:00:23.499460Z", datetime(2022, 12, 1, 13, 0, 23, 499460, tzinfo=UTC)),
        ("2019-09-26T07:58:30.996+0200", datetime(2019, 9, 26, 5, 58, 30, 996000, tzinfo=UTC)),
        ("2011-11-04T00:05:23+04:00", datetime(2011, 11, 3, 20, 5, 23, tzinfo=UTC)),
        ("2023-01-01T12:00:00+01:00", datetime(2023, 1, 1, 11, 0, 0, tzinfo=UTC)),
        ("2006-11-10T14:29:55.5851926", datetime(2006, 11, 10, 14, 29, 55, 585192, tzinfo=UTC)),
        ("2006-11-10T14:29:55.585192699999999", datetime(2006, 11, 10, 14, 29, 55, 585192, tzinfo=UTC)),
        (datetime(2023, 1, 1, tzinfo=UTC), datetime(2023, 1, 1, tzinfo=UTC)),
        (0, datetime(1970, 1, 1, 0, 0, tzinfo=UTC)),
        ("2023-09-01 13:37:12.345678+09:00", datetime(2023, 9, 1, 4, 37, 12, 345678, tzinfo=UTC)),
        ("2006-11-10T14:29:55.585192699999999-07:00", datetime(2006, 11, 10, 21, 29, 55, 585192, tzinfo=UTC)),
    ],
)
def test_datetime_formats(tmp_path: pathlib.Path, value: str, expected_dt: datetime) -> None:
    TestRecord = RecordDescriptor(
        "test/datetime",
        [
            ("datetime", "dt"),
        ],
    )
    record = TestRecord(dt=value)
    assert record.dt == expected_dt

    # test packing / serialization of datetime fields
    path = tmp_path / "datetime.records"
    with RecordWriter(path) as writer:
        writer.write(record)

    # test unpacking / deserialization of datetime fields
    with RecordReader(path) as reader:
        record = next(iter(reader))
        assert record.dt == expected_dt


def test_digest() -> None:
    TestRecord = RecordDescriptor(
        "test/digest",
        [
            ("digest", "digest"),
        ],
    )

    md5 = hashlib.md5(b"hello").hexdigest()
    sha1 = hashlib.sha1(b"hello").hexdigest()
    sha256 = hashlib.sha256(b"hello").hexdigest()

    record = TestRecord()
    assert isinstance(record.digest, flow.record.fieldtypes.digest)

    record = TestRecord((md5, sha1, sha256))
    assert record.digest.md5 == "5d41402abc4b2a76b9719d911017c592"
    assert record.digest.sha1 == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert record.digest.sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    record = TestRecord(("5d41402abc4b2a76b9719d911017c592", None, None))
    assert record.digest.md5 == "5d41402abc4b2a76b9719d911017c592"
    assert record.digest.sha1 is None
    assert record.digest.sha256 is None

    record = TestRecord()
    record.digest = (md5, sha1, sha256)
    assert record.digest.md5 == md5
    assert record.digest.sha1 == sha1
    assert record.digest.sha256 == sha256

    with pytest.raises(TypeError, match=r".*Invalid MD5.*Odd-length string"):
        record = TestRecord(("a", sha1, sha256))

    with pytest.raises(TypeError, match=r".*Invalid MD5.*Incorrect hash length"):
        record = TestRecord(("aa", sha1, sha256))

    with pytest.raises(TypeError, match=r".*Invalid SHA-1.*"):
        record = TestRecord((md5, "aa", sha256))

    with pytest.raises(TypeError, match=r".*Invalid SHA-256.*"):
        record = TestRecord((md5, sha1, "aa"))

    record = TestRecord()
    assert record.digest is not None
    assert record.digest.md5 is None
    assert record.digest.sha1 is None
    assert record.digest.sha256 is None
    with pytest.raises(TypeError, match=r".*Invalid MD5.*"):
        record.digest.md5 = "INVALID MD5"


def custom_pure_path(sep: str, altsep: str) -> pathlib.PurePath:
    # Starting from Python 3.12, pathlib._Flavours are removed as you can
    # now properly subclass pathlib.Path
    # The flavour property of Path's is replaced by a link to e.g.
    # posixpath or ntpath.
    # See also: https://github.com/python/cpython/issues/88302
    if PY_312_OR_HIGHER:

        class CustomFlavour:
            def __new__(cls, *args, **kwargs):
                flavour = types.ModuleType("mockpath")
                flavour.__dict__.update(posixpath.__dict__)
                flavour.sep = sep
                flavour.altsep = altsep
                return flavour

    else:

        class CustomFlavour(pathlib._PosixFlavour):
            def __new__(cls):
                instance = super().__new__(cls)
                instance.sep = sep
                instance.altsep = altsep
                return instance

    if PY_313_OR_HIGHER:

        class PureCustomPath(pathlib.PurePath):
            parser = CustomFlavour()

    else:

        class PureCustomPath(pathlib.PurePath):
            _flavour = CustomFlavour()

    return PureCustomPath


@pytest.mark.parametrize(
    ("path_", "is_posix"),
    [
        (pathlib.PurePosixPath("/foo/bar"), True),
        (pathlib.PureWindowsPath(r"C:\foo\bar"), False),
        (custom_pure_path(sep="/", altsep="")("/foo/bar"), True),
        (custom_pure_path(sep="\\", altsep="/")(r"C:\foo\bar"), False),
        (custom_pure_path(sep=":", altsep="\\")(r"C:\foo\bar"), False),
        ("/foo/bar", False),
    ],
)
def test__is_posixlike_path(path_: pathlib.PurePath | str, is_posix: bool) -> None:
    assert _is_posixlike_path(path_) == is_posix


@pytest.mark.parametrize(
    ("path_", "is_windows"),
    [
        (pathlib.PurePosixPath("/foo/bar"), False),
        (pathlib.PureWindowsPath(r"C:\foo\bar"), True),
        (custom_pure_path(sep="/", altsep="")("/foo/bar"), False),
        (custom_pure_path(sep="\\", altsep="/")(r"C:\foo\bar"), True),
        (custom_pure_path(sep=":", altsep="\\")(r"C:\foo\bar"), True),
        ("/foo/bar", False),
    ],
)
def test__is_windowslike_path(path_: pathlib.PurePath, is_windows: bool) -> None:
    assert _is_windowslike_path(path_) == is_windows


def test_path() -> None:
    TestRecord = RecordDescriptor(
        "test/path",
        [
            ("path", "value"),
        ],
    )

    posix_path_str = "/foo/bar.py"
    windows_path_str = "C:\\foo\\bar.py"

    r = TestRecord(pathlib.PurePosixPath(posix_path_str))
    assert str(r.value) == posix_path_str
    assert isinstance(r.value, flow.record.fieldtypes.posix_path)

    r = TestRecord()
    assert r.value is None

    r = TestRecord("")
    assert str(r.value) == ""
    assert r.value == ""

    if os.name == "nt":
        native_path_str = windows_path_str
        native_path_cls = flow.record.fieldtypes.windows_path
    else:
        native_path_str = posix_path_str
        native_path_cls = flow.record.fieldtypes.posix_path

    test_path = flow.record.fieldtypes.path(native_path_str)
    assert str(test_path) == native_path_str
    assert isinstance(test_path, native_path_cls)

    test_path = flow.record.fieldtypes.path(pathlib.PurePosixPath(posix_path_str))
    assert str(test_path) == posix_path_str
    assert isinstance(test_path, flow.record.fieldtypes.posix_path)

    test_path = flow.record.fieldtypes.path(pathlib.PureWindowsPath(windows_path_str))
    assert str(test_path) == windows_path_str
    assert isinstance(test_path, flow.record.fieldtypes.windows_path)

    test_path = flow.record.fieldtypes.path.from_posix(posix_path_str)
    assert str(test_path) == posix_path_str
    assert isinstance(test_path, flow.record.fieldtypes.posix_path)

    test_path = flow.record.fieldtypes.path.from_windows(windows_path_str)
    assert str(test_path) == windows_path_str
    assert isinstance(test_path, flow.record.fieldtypes.windows_path)

    test_path = flow.record.fieldtypes.path.from_posix(posix_path_str)
    assert test_path._pack() == (posix_path_str, TYPE_POSIX)

    test_path = flow.record.fieldtypes.path._unpack((posix_path_str, TYPE_POSIX))
    assert str(test_path) == posix_path_str
    assert isinstance(test_path, flow.record.fieldtypes.posix_path)

    test_path = flow.record.fieldtypes.path.from_windows(windows_path_str)
    assert test_path._pack() == (windows_path_str, TYPE_WINDOWS)

    test_path = flow.record.fieldtypes.path._unpack((windows_path_str, TYPE_WINDOWS))
    assert str(test_path) == windows_path_str
    assert isinstance(test_path, flow.record.fieldtypes.windows_path)

    test_path = flow.record.fieldtypes.path._unpack((posix_path_str, 2))
    assert str(test_path) == posix_path_str
    assert isinstance(test_path, flow.record.fieldtypes.posix_path)


@pytest.mark.parametrize(
    ("path_parts", "expected_instance"),
    [
        (
            ("/some/path", pathlib.PurePosixPath("pos/path"), pathlib.PureWindowsPath("win/path")),
            flow.record.fieldtypes.posix_path,
        ),
        (
            ("/some/path", pathlib.PureWindowsPath("win/path"), pathlib.PurePosixPath("pos/path")),
            flow.record.fieldtypes.windows_path,
        ),
        (
            (pathlib.PurePosixPath("pos/path"), pathlib.PureWindowsPath("win/path")),
            flow.record.fieldtypes.posix_path,
        ),
        (
            (pathlib.PureWindowsPath("win/path"), pathlib.PurePosixPath("pos/path")),
            flow.record.fieldtypes.windows_path,
        ),
        (
            (custom_pure_path(sep="/", altsep="")("pos/like"), pathlib.PureWindowsPath("win/path")),
            flow.record.fieldtypes.posix_path,
        ),
        (
            (custom_pure_path(sep="\\", altsep="/")("win/like"), pathlib.PurePosixPath("pos/path")),
            flow.record.fieldtypes.windows_path,
        ),
    ],
)
def test_path_multiple_parts(
    path_parts: tuple[str | pathlib.PurePath, ...], expected_instance: type[pathlib.PurePath]
) -> None:
    assert isinstance(flow.record.fieldtypes.path(*path_parts), expected_instance)


@pytest.mark.parametrize(
    "path_initializer",
    [
        flow.record.fieldtypes.posix_path,
        flow.record.fieldtypes.path.from_posix,
        pathlib.PurePosixPath,
    ],
)
@pytest.mark.parametrize(
    ("path", "expected_repr"),
    [
        ("/tmp/foo/bar", "/tmp/foo/bar"),
        ("\\tmp\\foo\\bar", r"\\tmp\\foo\\bar"),
        ("user/.bash_history", "user/.bash_history"),
    ],
)
def test_path_posix(path_initializer: Callable[[str], pathlib.PurePath], path: str, expected_repr: str) -> None:
    TestRecord = RecordDescriptor(
        "test/path",
        [
            ("path", "path"),
        ],
    )

    record = TestRecord(path=path_initializer(path))
    assert repr(record) == f"<test/path path='{expected_repr}'>"


@pytest.mark.parametrize(
    "path_initializer",
    [
        flow.record.fieldtypes.windows_path,
        flow.record.fieldtypes.path.from_windows,
        pathlib.PureWindowsPath,
    ],
)
@pytest.mark.parametrize(
    ("path", "expected_repr", "expected_str"),
    [
        ("c:\\windows\\temp\\foo\\bar", r"'c:\windows\temp\foo\bar'", r"c:\windows\temp\foo\bar"),
        (r"C:\Windows\Temp\foo\bar", r"'C:\Windows\Temp\foo\bar'", r"C:\Windows\Temp\foo\bar"),
        (r"d:/Users/Public", r"'d:\Users\Public'", r"d:\Users\Public"),
        (
            "/sysvol/Windows/System32/drivers/null.sys",
            r"'\sysvol\Windows\System32\drivers\null.sys'",
            r"\sysvol\Windows\System32\drivers\null.sys",
        ),
        (
            "/c:/Windows/System32/drivers/null.sys",
            r"'\c:\Windows\System32\drivers\null.sys'",
            r"\c:\Windows\System32\drivers\null.sys",
        ),
        ("Users\\Public", r"'Users\Public'", r"Users\Public"),
        (r"i:\don't.exe", '"i:\\don\'t.exe"', r"i:\don't.exe"),
        (
            'y:\\shakespeare\\"to be or not to be".txt',
            "'y:\\shakespeare\\\"to be or not to be\".txt'",
            'y:\\shakespeare\\"to be or not to be".txt',
        ),
        ("c:\\my'quotes\".txt", "'c:\\my\\'quotes\".txt'", "c:\\my'quotes\".txt"),
    ],
)
def test_path_windows(
    path_initializer: Callable[[str], pathlib.PurePath], path: str, expected_repr: str, expected_str: str
) -> None:
    TestRecord = RecordDescriptor(
        "test/path",
        [
            ("path", "path"),
        ],
    )
    record = TestRecord(path=path_initializer(path))
    assert repr(record) == f"<test/path path={expected_repr}>"
    assert repr(record.path) == expected_repr
    assert str(record.path) == expected_str


def test_windows_path_eq() -> None:
    path = windows_path("c:\\windows\\test.exe")
    assert path == "c:\\windows\\test.exe"
    assert path == "c:/windows/test.exe"
    assert path == "c:/windows\\test.exe"
    assert path == "c:\\WINDOWS\\tEsT.ExE"
    assert path != "c:/windows\\test2.exe"
    assert path == windows_path("c:\\windows\\test.exe")
    assert path != posix_path("c:\\windows\\test.exe")


def test_posix_path_eq() -> None:
    path = posix_path("/usr/local/bin/test")
    assert path == "/usr/local/bin/test"
    assert path != "\\usr\\local\\bin\\test"
    assert path != "/usr/local/bin/test2"
    assert path != "/uSr/lOcAl/bIn/tEst"
    assert path == posix_path("/usr/local/bin/test")
    assert path != windows_path("/usr/local/bin/test2")


def test_fieldtype_for_value() -> None:
    assert fieldtype_for_value(True) == "boolean"
    assert fieldtype_for_value(False) == "boolean"
    assert fieldtype_for_value(1337) == "varint"
    assert fieldtype_for_value(1.337) == "float"
    assert fieldtype_for_value(b"\r\n") == "bytes"
    assert fieldtype_for_value("hello world") == "string"
    assert fieldtype_for_value(datetime.now()) == "datetime"  # noqa: DTZ005
    assert fieldtype_for_value([1, 2, 3, 4, 5]) == "string"
    assert fieldtype_for_value([1, 2, 3, 4, 5], None) is None
    assert fieldtype_for_value(object(), None) is None
    assert fieldtype_for_value(pathlib.PurePosixPath("/foo/bar.py")) == "path"


def test_dynamic() -> None:
    TestRecord = RecordDescriptor(
        "test/dynamic",
        [
            ("dynamic", "value"),
        ],
    )

    r = TestRecord(b"bytes")
    assert r.value == b"bytes"
    assert isinstance(r.value, flow.record.fieldtypes.bytes)

    r = TestRecord("string")
    assert r.value == "string"
    assert isinstance(r.value, flow.record.fieldtypes.string)

    r = TestRecord(123)
    assert r.value == 123
    assert isinstance(r.value, flow.record.fieldtypes.varint)

    r = TestRecord(True)
    assert r.value
    assert isinstance(r.value, flow.record.fieldtypes.boolean)

    r = TestRecord([1, 2, 3])
    assert r.value == [1, 2, 3]
    assert isinstance(r.value, flow.record.fieldtypes.stringlist)

    now = datetime.now(UTC)
    r = TestRecord(now)
    assert r.value == now
    assert isinstance(r.value, flow.record.fieldtypes.datetime)

    path_str = "/foo/bar.py"
    r = TestRecord(flow.record.fieldtypes.path.from_posix(path_str))
    assert str(r.value) == path_str
    assert isinstance(r.value, flow.record.fieldtypes.posix_path)


@pytest.mark.parametrize(
    ("record_type", "value", "expected"),
    [
        ("uri", "https://www.fox-it.com/nl-en/dissect/", "hxxps://www.fox-it[.]com/nl-en/dissect/"),
        ("string", "https://www.fox-it.com/nl-en/dissect/", "hxxps://www.fox-it[.]com/nl-en/dissect/"),
        ("uri", "http://docs.dissect.tools", "hxxp://docs.dissect[.]tools"),
        (
            "string",
            "http://username:password@example.com/path/file.txt?query=1",
            "hxxp://username:password@example[.]com/path/file.txt?query=1",
        ),
        ("net.ipaddress", "1.3.3.7", "1.3.3[.]7"),
        ("string", "www.fox-it.com", "www.fox-it[.]com"),
        ("string", "dissect.tools", "dissect[.]tools"),
        ("uri", "HTtPs://SpOngEbOB.cOm", "hxxps://SpOngEbOB[.]cOm"),
        ("uri", "ftp://user:password@127.0.0.1:21/", "fxp://user:password@127.0.0[.]1:21/"),
        (
            "uri",
            "https://isc.sans.edu/forums/diary/Defang+all+the+things/22744/",
            "hxxps://isc.sans[.]edu/forums/diary/Defang+all+the+things/22744/",
        ),
    ],
)
def test_format_defang(record_type: str, value: str, expected: str) -> None:
    TestRecord = RecordDescriptor(
        "test/format/defang",
        [
            (record_type, "value"),
        ],
    )

    record = TestRecord(value)
    assert f"{record.value:defang}" == expected
    assert f"{record.value:>100}" == f"{value:>100}"


@pytest.mark.parametrize(
    ("spec", "value", "expected"),
    [
        ("x", b"\xac\xce\x55\xed", "acce55ed"),
        ("X", b"\xac\xce\x55\xed", "ACCE55ED"),
        ("#x", b"\xac\xce\x55\xed", "0xacce55ed"),
        ("#X", b"\xac\xce\x55\xed", "0xACCE55ED"),
        ("hex", b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e", "000102030405060708090a0b0c0d0e"),
        ("HEX", b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e", "000102030405060708090A0B0C0D0E"),
        ("x", b"", ""),
    ],
)
def test_format_hex(spec: str, value: bytes, expected: str) -> None:
    TestRecord = RecordDescriptor(
        "test/format/hex",
        [
            ("bytes", "value"),
        ],
    )

    record = TestRecord(value)
    format_str = "{:" + spec + "}"
    assert format_str.format(record.value) == expected


@pytest.mark.parametrize(
    "filename",
    [
        "test.records",
        "test.records.gz",
        "test.records.json",
    ],
)
@pytest.mark.parametrize(
    ("str_bytes", "unicode_errors", "expected_str"),
    [
        (b"hello \xa7 world", "surrogateescape", "hello \udca7 world"),
        (b"hello \xa7 world", "backslashreplace", "hello \\xa7 world"),
        (b"hello \xa7 world", "replace", "hello \ufffd world"),
        (b"hello \xa7 world", "ignore", "hello  world"),
    ],
)
def test_string_serialization(
    tmp_path: pathlib.Path, filename: str, str_bytes: bytes, unicode_errors: str, expected_str: str
) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "str_value"),
        ],
    )

    str_value = str_bytes.decode("utf-8", errors=unicode_errors)
    record = TestRecord(str_value=str_value)
    assert str_value == expected_str
    assert record.str_value == expected_str

    with RecordWriter(tmp_path / filename) as writer:
        writer.write(record)

    with RecordReader(tmp_path / filename) as reader:
        record = next(iter(reader))
        assert str(record.str_value) == expected_str
        assert record.str_value == expected_str


def test_datetime_strip_nanoseconds() -> None:
    d1 = dt("1984-01-01T08:10:12.123456789Z")
    d2 = dt("1984-01-01T08:10:12.123456Z")
    assert isinstance(d1, dt)
    assert isinstance(d2, dt)
    assert d1 == d2


def test_datetime_handle_nanoseconds_without_timezone() -> None:
    d1 = dt("2006-11-10T14:29:55.5851926")
    d2 = dt("2006-11-10T14:29:55")
    assert isinstance(d1, dt)
    assert isinstance(d2, dt)
    assert d1 == datetime(2006, 11, 10, 14, 29, 55, 585192, tzinfo=UTC)
    assert d1.microsecond == 585192
    assert d2 == datetime(2006, 11, 10, 14, 29, 55, tzinfo=UTC)
    assert d2.microsecond == 0


@pytest.mark.parametrize(
    "record_filename",
    [
        "out.records.gz",
        "out.records",
        "out.json",
        "out.jsonl",
    ],
)
def test_datetime_timezone_aware(tmp_path: pathlib.Path, record_filename: str) -> None:
    TestRecord = RecordDescriptor(
        "test/tz",
        [
            ("datetime", "ts"),
        ],
    )
    tz = timezone(timedelta(hours=1))
    stamp = datetime.now(tz)

    with RecordWriter(tmp_path / record_filename) as writer:
        record = TestRecord(stamp)
        writer.write(record)
        assert record.ts == stamp
        assert record.ts.utcoffset() == timedelta(hours=1)
        assert record._generated.tzinfo == UTC

    with RecordReader(tmp_path / record_filename) as reader:
        for record in reader:
            assert record.ts == stamp
            assert record.ts.utcoffset() == timedelta(hours=1)
            assert record._generated.tzinfo == UTC


def test_datetime_comparisions() -> None:
    with pytest.raises(TypeError, match=".* compare .*naive"):
        assert dt("2023-01-01") > datetime(2022, 1, 1)  # noqa: DTZ001

    with pytest.raises(TypeError, match=".* compare .*naive"):
        assert datetime(2022, 1, 1) < dt("2023-01-01")  # noqa: DTZ001

    assert dt("2023-01-01") > datetime(2022, 1, 1, tzinfo=UTC)
    assert dt("2023-01-01") == datetime(2023, 1, 1, tzinfo=UTC)
    assert dt("2023-01-01") == datetime(2023, 1, 1, tzinfo=UTC)
    assert dt("2023-01-01T13:36") <= datetime(2023, 1, 1, 13, 37, tzinfo=UTC)
    assert dt("2023-01-01T13:37") <= datetime(2023, 1, 1, 13, 37, tzinfo=UTC)
    assert dt("2023-01-01T13:37") >= datetime(2023, 1, 1, 13, 36, tzinfo=UTC)
    assert dt("2023-01-01T13:37") >= datetime(2023, 1, 1, 13, 37, tzinfo=UTC)
    assert dt("2023-01-01T13:36") < datetime(2023, 1, 1, 13, 37, tzinfo=UTC)
    assert dt("2023-01-01T13:37") > datetime(2023, 1, 1, 13, 36, tzinfo=UTC)
    assert dt("2023-01-02") != datetime(2023, 3, 4, tzinfo=UTC)


def test_command_record() -> None:
    TestRecord = RecordDescriptor(
        "test/command",
        [
            ("command", "commando"),
        ],
    )

    record = TestRecord(commando="help.exe -h")
    assert isinstance(record.commando, posix_command)
    assert record.commando.executable == "help.exe"
    assert record.commando.args == ["-h"]

    record = TestRecord(commando="something.so -h -q -something")
    assert isinstance(record.commando, posix_command)
    assert record.commando.executable == "something.so"
    assert record.commando.args == ["-h", "-q", "-something"]


def test_command_integration(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "test/command",
        [
            ("command", "commando"),
        ],
    )

    with RecordWriter(tmp_path / "command_record") as writer:
        record = TestRecord(commando=r"\\.\\?\some_command.exe -h,help /d quiet")
        writer.write(record)
        assert record.commando.executable == r"\\.\\?\some_command.exe"
        assert record.commando.args == [r"-h,help /d quiet"]

    with RecordReader(tmp_path / "command_record") as reader:
        for record in reader:
            assert record.commando.executable == r"\\.\\?\some_command.exe"
            assert record.commando.args == [r"-h,help /d quiet"]


def test_command_integration_none(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "test/command",
        [
            ("command", "commando"),
        ],
    )

    with RecordWriter(tmp_path / "command_record") as writer:
        record = TestRecord(commando=command.from_posix(None))
        writer.write(record)
    with RecordReader(tmp_path / "command_record") as reader:
        for record in reader:
            assert record.commando.executable is None
            assert record.commando.args is None


@pytest.mark.parametrize(
    ("command_string", "expected_executable", "expected_argument"),
    [
        # Test relative windows paths
        ("windows.exe something,or,somethingelse", "windows.exe", ["something,or,somethingelse"]),
        # Test weird command strings for windows
        ("windows.dll something,or,somethingelse", "windows.dll", ["something,or,somethingelse"]),
        # Test environment variables
        (r"%WINDIR%\\windows.dll something,or,somethingelse", r"%WINDIR%\\windows.dll", ["something,or,somethingelse"]),
        # Test a quoted path
        (r"'c:\path to some exe' /d /a", r"c:\path to some exe", [r"/d /a"]),
        # Test a unquoted path
        (r"\Users\test\hello.exe", r"\Users\test\hello.exe", []),
        # Test an unquoted path with a path as argument
        (r"\Users\test\hello.exe c:\startmepls.exe", r"\Users\test\hello.exe", [r"c:\startmepls.exe"]),
        # Test a quoted UNC path
        (r"'\\192.168.1.2\Program Files\hello.exe'", r"\\192.168.1.2\Program Files\hello.exe", []),
        # Test an unquoted UNC path
        (r"\\192.168.1.2\Users\test\hello.exe /d /a", r"\\192.168.1.2\Users\test\hello.exe", [r"/d /a"]),
        # Test an empty command string
        (r"''", r"", []),
        # Test None
        (None, None, None),
    ],
)
def test_command_windows(command_string: str, expected_executable: str, expected_argument: list[str]) -> None:
    cmd = windows_command(command_string)

    assert cmd.executable == expected_executable
    assert cmd.args == expected_argument


@pytest.mark.parametrize(
    ("command_string", "expected_executable", "expected_argument"),
    [
        # Test relative posix command
        ("some_file.so -h asdsad -f asdsadas", "some_file.so", ["-h", "asdsad", "-f", "asdsadas"]),
        # Test command with spaces
        (r"/bin/hello\ world -h -word", r"/bin/hello world", ["-h", "-word"]),
    ],
)
def test_command_posix(command_string: str, expected_executable: str, expected_argument: list[str]) -> None:
    cmd = posix_command(command_string)

    assert cmd.executable == expected_executable
    assert cmd.args == expected_argument


def test_command_equal() -> None:
    assert command("hello.so -h") == command("hello.so -h")
    assert command("hello.so -h") != command("hello.so")

    # Test different types with the comparitor
    assert command("hello.so -h") == ["hello.so", "-h"]
    assert command("hello.so -h") == ("hello.so", "-h")
    assert command("hello.so -h") == "hello.so -h"
    assert command("c:\\hello.dll -h -b") == "c:\\hello.dll -h -b"

    # Compare paths that contain spaces
    assert command("'/home/some folder/file' -h") == "'/home/some folder/file' -h"
    assert command("'c:\\Program files\\some.dll' -h -q") == "'c:\\Program files\\some.dll' -h -q"
    assert command("'c:\\program files\\some.dll' -h -q") == ["c:\\program files\\some.dll", "-h -q"]
    assert command("'c:\\Program files\\some.dll' -h -q") == ("c:\\Program files\\some.dll", "-h -q")

    # Test failure conditions
    assert command("hello.so -h") != 1
    assert command("hello.so") != "hello.so -h"
    assert command("hello.so") != ["hello.so", ""]
    assert command("hello.so") != ("hello.so", "")


def test_command_failed() -> None:
    with pytest.raises(TypeError, match="Expected a value of type 'str'"):
        command(b"failed")


@pytest.mark.parametrize(
    "path_cls",
    [
        fieldtypes.posix_path,
        fieldtypes.windows_path,
        fieldtypes.path,
    ],
)
def test_empty_path(path_cls: type[pathlib.PurePath]) -> None:
    # initialize with empty string
    p1 = path_cls("")
    assert p1 == ""
    assert p1._empty_path
    assert str(p1) == ""
    assert p1 != path_cls(".")
    assert path_cls(".") != p1

    # initialize without any arguments
    p2 = path_cls()
    assert p2 == ""
    assert p2._empty_path
    assert str(p2) == ""
    assert p2 != path_cls(".")
    assert path_cls(".") != p2

    assert p1 == p2


def test_empty_path_different_types() -> None:
    assert fieldtypes.posix_path("") != fieldtypes.windows_path("")


def test_record_empty_path() -> None:
    TestRecord = RecordDescriptor(
        "test/path",
        [
            ("path", "value"),
        ],
    )

    r = TestRecord()
    assert r.value is None
    assert repr(r) == "<test/path value=None>"

    r = TestRecord("")
    assert r.value == ""
    assert repr(r) == "<test/path value=''>"


def test_empty_path_serialization(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "test/path",
        [
            ("path", "value"),
        ],
    )

    # Test path value=None serialization
    p_tmp_records = tmp_path / "none_path"
    with RecordWriter(p_tmp_records) as writer:
        record = TestRecord()
        writer.write(record)
    with RecordReader(p_tmp_records) as reader:
        for record in reader:
            assert record.value is None

    # Test path value="" serialization
    p_tmp_records = tmp_path / "empty_str"
    with RecordWriter(p_tmp_records) as writer:
        record = TestRecord("")
        writer.write(record)
    with RecordReader(p_tmp_records) as reader:
        for record in reader:
            assert record.value == ""


def test_empty_windows_path_parent() -> None:
    # test that the parent of an empty path is also an empty path
    path = fieldtypes.windows_path("")
    assert path.parent == ""
    assert path.parent.parent == ""
    assert path._empty_path
    assert path.parent._empty_path
    assert list(path.parents) == []

    path = fieldtypes.windows_path("c:/windows/temp")
    assert path.parent == "c:/windows"
    assert path.parent.parent == "c:/"
    assert path.parent.parent.parent == "c:/"
    assert not path.parent._empty_path
    assert not path._empty_path
    assert list(path.parents) == ["c:/windows", "c:/"]


def test_empty_posix_path_parent() -> None:
    # test that the parent of an empty path is also an empty path
    path = fieldtypes.posix_path("")
    assert path.parent == ""
    assert path.parent.parent == ""
    assert path._empty_path
    assert path.parent._empty_path
    assert list(path.parents) == []

    path = fieldtypes.posix_path("/var/log")
    assert path.parent == "/var"
    assert path.parent.parent == "/"
    assert path.parent.parent.parent == "/"
    assert not path.parent._empty_path
    assert not path._empty_path
    assert list(path.parents) == ["/var", "/"]


if __name__ == "__main__":
    __import__("standalone_test").main(globals())
