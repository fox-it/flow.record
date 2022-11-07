# coding: utf-8

import datetime
import hashlib
import os
import pathlib

import pytest

from flow.record import RecordDescriptor
from flow.record.fieldtypes import net
from flow.record.fieldtypes import uri
from flow.record.fieldtypes import fieldtype_for_value
from flow.record.fieldtypes import PATH_POSIX, PATH_WINDOWS
import flow.record.fieldtypes

INT64_MAX = (1 << 63) - 1
INT32_MAX = (1 << 31) - 1
INT16_MAX = (1 << 15) - 1

UINT128_MAX = (1 << 128) - 1
UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
UINT16_MAX = (1 << 16) - 1


def test_uint16():
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
    with pytest.raises(ValueError):
        desc.recordType(-1)

    with pytest.raises(ValueError):
        desc.recordType(UINT16_MAX + 1)

    with pytest.raises((ValueError, OverflowError)):
        desc.recordType(UINT128_MAX)


def test_uint32():
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
    with pytest.raises(ValueError):
        TestRecord(-1)

    with pytest.raises(ValueError):
        TestRecord(UINT32_MAX + 1)

    with pytest.raises((ValueError, OverflowError)):
        TestRecord(UINT128_MAX)


def test_net_ipv4_address():
    TestRecord = RecordDescriptor(
        "test/net/ipv4/address",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )

    TestRecord("1.1.1.1")
    TestRecord("0.0.0.0")
    TestRecord("192.168.0.1")
    TestRecord("255.255.255.255")

    r = TestRecord("127.0.0.1")

    assert isinstance(r.ip, net.ipv4.Address)

    for invalid in ["1.1.1.256", "192.168.0.1/24", "a.b.c.d"]:
        with pytest.raises(Exception) as excinfo:
            TestRecord(invalid)
        excinfo.match(r".*illegal IP address string.*")

    r = TestRecord()
    assert r.ip is None


def test_net_ipv4_subnet():
    TestRecord = RecordDescriptor(
        "test/net/ipv4/subnet",
        [
            ("net.ipv4.Subnet", "subnet"),
        ],
    )

    r = TestRecord("1.1.1.0/24")
    assert str(r.subnet) == "1.1.1.0/24"

    assert "1.1.1.1" in r.subnet
    assert "1.1.1.2" in r.subnet

    assert "1.1.2.1" not in r.subnet
    # assert "1.1.1.1/32" not in r.subnet

    r = TestRecord("0.0.0.0")
    r = TestRecord("192.168.0.1")
    r = TestRecord("255.255.255.255")

    r = TestRecord("127.0.0.1")

    for invalid in ["a.b.c.d", "foo", "bar", ""]:
        with pytest.raises(Exception) as excinfo:
            TestRecord(invalid)
        excinfo.match(r".*illegal IP address string.*")

    for invalid in [1, 1.0, sum, dict(), list(), True]:
        with pytest.raises(TypeError) as excinfo:
            TestRecord(invalid)
        excinfo.match(r"Subnet\(\) argument 1 must be string, not .*")

    with pytest.raises(ValueError) as excinfo:
        TestRecord("192.168.0.106/28")
    excinfo.match(r"Not a valid subnet '192\.168\.0\.106/28', did you mean '192\.168\.0\.96/28' ?")


def test_bytes():
    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("string", "url"),
            ("bytes", "body"),
        ],
    )

    r = TestRecord("url", b"some bytes")
    assert r.body == b"some bytes"

    with pytest.raises(TypeError) as excinfo:
        r = TestRecord("url", 1234)
        excinfo.match(r"Value not of bytes type")

    with pytest.raises(TypeError) as excinfo:
        r = TestRecord("url", "a string")
        excinfo.match(r"Value not of bytes type")

    b_array = bytes(bytearray(range(256)))
    body = b"HTTP/1.1 200 OK\r\n\r\n" + b_array
    r = TestRecord("http://www.fox-it.com", body)
    assert r
    assert r.url == "http://www.fox-it.com"
    assert r.body == b"HTTP/1.1 200 OK\r\n\r\n" + b_array

    # testcase when input are bytes
    r = TestRecord("http://www.fox-it.com", b"HTTP/1.1 500 Error\r\n\r\nError")
    assert r.body == b"HTTP/1.1 500 Error\r\n\r\nError"


def test_string():
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
    if isinstance("", str):
        # Python 3
        with pytest.raises(UnicodeDecodeError):
            TestRecord(b"R\xc3\xa9\xeamy")
    else:
        # Python 2
        with pytest.warns(RuntimeWarning):
            r = TestRecord(b"R\xc3\xa9\xeamy")
            assert r.name


def test_wstring():
    # Behaves the same as test/string, only available for backwards compatibility purposes
    TestRecord = RecordDescriptor(
        "test/wstring",
        [
            ("wstring", "name"),
        ],
    )

    r = TestRecord("Fox-IT")
    assert r.name == "Fox-IT"


def test_typedlist():
    TestRecord = RecordDescriptor(
        "test/typedlist",
        [
            ("string[]", "string_value"),
            ("uint32[]", "uint32_value"),
            ("uri[]", "uri_value"),
        ],
    )

    r = TestRecord(["a", "b", "c"], [1, 2, 3], ["/etc/passwd", "/etc/shadow"])
    assert len(r.string_value) == 3
    assert len(r.uint32_value) == 3
    assert len(r.uri_value) == 2
    assert r.string_value[2] == "c"
    assert r.uint32_value[1] == 2
    assert all([isinstance(v, uri) for v in r.uri_value])
    assert r.uri_value[1].filename == "shadow"

    r = TestRecord()
    assert r.string_value == []
    assert r.uint32_value == []
    assert r.uri_value == []

    with pytest.raises(ValueError):
        r = TestRecord(uint32_value=["a", "b", "c"])


def test_stringlist():
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


def test_dictlist():
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


def test_boolean():
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

    with pytest.raises(ValueError):
        r = TestRecord(2, -1)

    with pytest.raises(ValueError):
        r = TestRecord("True", "False")


def test_float():
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
    with pytest.raises(ValueError):
        r = TestRecord("abc")


def test_uri_type():
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

    with pytest.warns(DeprecationWarning):
        r = TestRecord(uri.from_windows(r"c:\windows\program files\Fox-IT B.V\flow.exe"))
    assert r.path.filename == "flow.exe"

    r = TestRecord()
    with pytest.warns(DeprecationWarning):
        r.path = uri.normalize(r"c:\Users\Fox-IT\Downloads\autoruns.exe")
    assert r.path.filename == "autoruns.exe"
    with pytest.warns(DeprecationWarning):
        assert r.path.dirname == uri.normalize(r"\Users\Fox-IT\Downloads")
    assert r.path.dirname == "/Users/Fox-IT/Downloads"

    r = TestRecord()
    r.path = "/usr/local/bin/sshd"
    assert r.path.filename == "sshd"
    assert r.path.dirname == "/usr/local/bin"


def test_datetime():
    TestRecord = RecordDescriptor(
        "test/datetime",
        [
            ("datetime", "ts"),
        ],
    )

    now = datetime.datetime.utcnow()
    r = TestRecord(now)
    assert r.ts == now

    r = TestRecord("2018-03-22T15:15:23")
    assert r.ts == datetime.datetime(2018, 3, 22, 15, 15, 23)

    r = TestRecord("2018-03-22T15:15:23.000000")
    assert r.ts == datetime.datetime(2018, 3, 22, 15, 15, 23)

    r = TestRecord("2018-03-22T15:15:23.123456")
    assert r.ts == datetime.datetime(2018, 3, 22, 15, 15, 23, 123456)

    dt = datetime.datetime(2018, 3, 22, 15, 15, 23, 123456)
    dt_str = dt.isoformat()
    r = TestRecord(dt_str)
    assert r.ts == dt

    r = TestRecord(1521731723)
    assert r.ts == datetime.datetime(2018, 3, 22, 15, 15, 23)

    r = TestRecord(1521731723.123456)
    assert r.ts == datetime.datetime(2018, 3, 22, 15, 15, 23, 123456)


def test_digest():
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

    with pytest.raises(TypeError) as excinfo:
        record = TestRecord(("a", sha1, sha256))
        excinfo.match(r".*Invalid MD5.*Odd-length string")

    with pytest.raises(TypeError) as excinfo:
        record = TestRecord(("aa", sha1, sha256))
        excinfo.match(r".*Invalid MD5.*Incorrect hash length")

    with pytest.raises(TypeError) as excinfo:
        record = TestRecord((md5, "aa", sha256))
        excinfo.match(r".*Invalid SHA1.*")

    with pytest.raises(TypeError) as excinfo:
        record = TestRecord((md5, sha1, "aa"))
        excinfo.match(r".*Invalid SHA256.*")

    record = TestRecord()
    assert record.digest is not None
    assert record.digest.md5 is None
    assert record.digest.sha1 is None
    assert record.digest.sha256 is None
    with pytest.raises(TypeError) as excinfo:
        record.digest.md5 = "INVALID MD5"
        excinfo.match(r".*Invalid MD5.*")


def test_path():
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
    assert str(r.value) == "."

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
    assert test_path._pack() == (posix_path_str, PATH_POSIX)

    test_path = flow.record.fieldtypes.path._unpack((posix_path_str, PATH_POSIX))
    assert str(test_path) == posix_path_str
    assert isinstance(test_path, flow.record.fieldtypes.posix_path)

    test_path = flow.record.fieldtypes.path.from_windows(windows_path_str)
    assert test_path._pack() == (windows_path_str, PATH_WINDOWS)

    test_path = flow.record.fieldtypes.path._unpack((windows_path_str, PATH_WINDOWS))
    assert str(test_path) == windows_path_str
    assert isinstance(test_path, flow.record.fieldtypes.windows_path)

    test_path = flow.record.fieldtypes.path._unpack((posix_path_str, 2))
    assert str(test_path) == posix_path_str
    assert isinstance(test_path, flow.record.fieldtypes.posix_path)


def test_fieldtype_for_value():
    assert fieldtype_for_value(True) == "boolean"
    assert fieldtype_for_value(False) == "boolean"
    assert fieldtype_for_value(1337) == "varint"
    assert fieldtype_for_value(1.337) == "float"
    assert fieldtype_for_value(b"\r\n") == "bytes"
    assert fieldtype_for_value("hello world") == "string"
    assert fieldtype_for_value(datetime.datetime.now()) == "datetime"
    assert fieldtype_for_value([1, 2, 3, 4, 5]) == "string"
    assert fieldtype_for_value([1, 2, 3, 4, 5], None) is None
    assert fieldtype_for_value(object(), None) is None
    assert fieldtype_for_value(pathlib.PurePosixPath("/foo/bar.py")) == "path"


def test_dynamic():
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

    now = datetime.datetime.utcnow()
    r = TestRecord(now)
    assert r.value == now
    assert isinstance(r.value, flow.record.fieldtypes.datetime)

    path_str = "/foo/bar.py"
    r = TestRecord(flow.record.fieldtypes.path.from_posix(path_str))
    assert str(r.value) == path_str
    assert isinstance(r.value, flow.record.fieldtypes.posix_path)


@pytest.mark.parametrize(
    "record_type,value,expected",
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
def test_format_defang(record_type, value, expected):
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
    "spec,value,expected",
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
def test_format_hex(spec, value, expected):
    TestRecord = RecordDescriptor(
        "test/format/hex",
        [
            ("bytes", "value"),
        ],
    )

    record = TestRecord(value)
    format_str = "{:" + spec + "}"
    assert format_str.format(record.value) == expected


if __name__ == "__main__":
    __import__("standalone_test").main(globals())
