from __future__ import annotations

import codecs
import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Callable
from unittest.mock import MagicMock, patch

import msgpack
import pytest

from flow.record import (
    RECORD_VERSION,
    GroupedRecord,
    Record,
    RecordDescriptor,
    RecordPacker,
    RecordReader,
    RecordWriter,
    base,
    fieldtypes,
    whitelist,
)
from flow.record.base import _generate_record_class, fieldtype, is_valid_field_name
from flow.record.packer import RECORD_PACK_EXT_TYPE, RECORD_PACK_TYPE_RECORD
from flow.record.selector import CompiledSelector, Selector
from flow.record.tools import rdump
from flow.record.utils import is_stdout


def test_datetime_serialization() -> None:
    packer = RecordPacker()

    now = datetime.now(timezone.utc)

    for tz in ["UTC", "Europe/Amsterdam"]:
        os.environ["TZ"] = tz

        descriptor = RecordDescriptor(
            "test/datetime",
            [
                ("datetime", "datetime"),
            ],
        )

        record = descriptor.recordType(datetime=now)
        data = packer.pack(record)
        r = packer.unpack(data)

        assert r.datetime == now


def test_long_int_serialization() -> None:
    packer = RecordPacker()

    long_types = RecordDescriptor(
        "test/long_types",
        [
            ("varint", "long_type"),
            ("varint", "int_type"),
            ("varint", "long_type_neg"),
            ("varint", "int_type_neg"),
            ("varint", "max_int_as_long"),
        ],
    )

    l = 1239812398217398127398217389217389217398271398217321  # noqa: E741
    i = 888888
    lneg = -3239812398217398127398217389217389217398271398217321
    ineg = -988888
    max_int_as_long = sys.maxsize

    record = long_types(l, i, lneg, ineg, max_int_as_long)
    data = packer.pack(record)
    r = packer.unpack(data)

    assert r.long_type == l
    assert r.int_type == i
    assert r.long_type_neg == lneg
    assert r.int_type_neg == ineg
    assert r.max_int_as_long == max_int_as_long


def test_unicode_serialization() -> None:
    packer = RecordPacker()

    descriptor = RecordDescriptor(
        "test/unicode",
        [
            ("string", "text"),
        ],
    )

    puny_domains = [b"xn--s7y.co", b"xn--80ak6aa92e.com", b"xn--pple-43d.com"]

    for p in puny_domains:
        domain = codecs.decode(p, "idna")
        record = descriptor.recordType(text=domain)
        d = packer.pack(record)
        record2 = packer.unpack(d)

        assert record.text == record2.text
        assert record.text == domain


def test_pack_long_int_serialization() -> None:
    packer = RecordPacker()
    # test if 'long int' that fit in the 'int' type would be packed as int internally

    max_neg_int = -0x8000000000000000
    d = packer.pack([1234, 123456, max_neg_int, sys.maxsize])
    assert (
        d
        == b"\x94\xcd\x04\xd2\xce\x00\x01\xe2@\xd3\x80\x00\x00\x00\x00\x00\x00\x00\xcf\x7f\xff\xff\xff\xff\xff\xff\xff"
    )


def test_non_existing_field() -> None:
    # RecordDescriptor that is used to test locally in the Broker client
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "text"),
        ],
    )
    x = TestRecord(text="Fox-IT, For a More Secure Society")

    # r.content does not exist in the RecordDescriptor
    assert Selector('lower("Fox-IT") in lower(r.content)').match(x) is False
    assert Selector('"Fox-IT" in r.content').match(x) is False
    # because the field does not exist, it will still evaluate to False even for negative matches
    assert Selector('"Fox-IT" not in r.content').match(x) is False
    assert Selector('"Fox-IT" in r.content').match(x) is False
    assert Selector('"Fox-IT" != r.content').match(x) is False
    assert Selector('"Fox-IT" == r.content').match(x) is False
    assert Selector('r.content == "Fox-IT, For a More Secure Society"').match(x) is False
    assert Selector('r.content != "Fox-IT, For a More Secure Society"').match(x) is False
    assert Selector('r.content in "Fox-IT, For a More Secure Society!"').match(x) is False
    assert Selector('r.content not in "Fox-IT, For a More Secure Society!"').match(x) is False

    # r.text exist in the RecordDescriptor
    assert Selector('"fox-it" in lower(r.text)').match(x)
    assert Selector('r.text in "Fox-IT, For a More Secure Society!!"').match(x)
    assert Selector('r.text == "Fox-IT, For a More Secure Society"').match(x)
    assert Selector('r.text != "Fox-IT"').match(x)
    assert Selector('lower("SECURE") in lower(r.text)').match(x)
    assert Selector('"f0x-1t" not in lower(r.text)').match(x)
    assert Selector('lower("NOT SECURE") not in lower(r.text)').match(x)


def test_set_field_type() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "value"),
        ],
    )

    r = TestRecord(1)

    assert isinstance(r.value, fieldtypes.uint32)
    r.value = 2
    assert isinstance(r.value, fieldtypes.uint32)

    with pytest.raises(ValueError, match="invalid literal for int"):
        r.value = "lalala"
    r.value = 2

    r = TestRecord()
    assert r.value is None
    r.value = 1234
    assert r.value == 1234
    with pytest.raises(TypeError):
        r.value = [1, 2, 3, 4, 5]


def test_packer_unpacker_none_values() -> None:
    """Tests packing and unpacking of Empty records (default values of None)."""
    packer = RecordPacker()

    # construct field types from all available fieldtypes
    field_tuples = []
    for typename in whitelist.WHITELIST:
        fieldname = "field_{}".format(typename.replace(".", "_").lower())
        field_tuples.append((typename, fieldname))

    # create a TestRecord descriptor containing all the fieldtypes
    TestRecord = RecordDescriptor("test/empty_record", field_tuples)

    # initialize an Empty record and serialize/deserialize
    record = TestRecord()
    data = packer.pack(record)
    r = packer.unpack(data)
    assert isinstance(r, Record)


def test_fieldname_regression() -> None:
    TestRecord = RecordDescriptor(
        "test/uri_typed",
        [
            ("string", "fieldname"),
        ],
    )
    rec = TestRecord("omg regression")

    assert rec in Selector("r.fieldname == 'omg regression'")

    with pytest.raises(AttributeError):
        assert rec not in Selector("fieldname == 'omg regression'")


def test_version_field_regression() -> None:
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "value"),
        ],
    )

    r = TestRecord(1)

    assert r.__slots__[-1] == "_version"

    r._version = 256
    data = packer.pack(r)
    with pytest.warns(RuntimeWarning) as record:
        packer.unpack(data)

    assert len(record) == 1
    assert record[0].message.args[0].startswith("Got old style record with no version information")

    r._version = RECORD_VERSION + 1 if RECORD_VERSION < 255 else RECORD_VERSION - 1
    data = packer.pack(r)
    with pytest.warns(RuntimeWarning) as record:
        packer.unpack(data)

    assert len(record) == 1
    assert record[0].message.args[0].startswith("Got other version record")


def test_reserved_field_count_regression() -> None:
    del base.RESERVED_FIELDS["_version"]
    base.RESERVED_FIELDS["_extra"] = "varint"
    base.RESERVED_FIELDS["_version"] = "varint"

    RecordDescriptor.get_required_fields.cache_clear()
    _generate_record_class.cache_clear()
    TestRecordExtra = RecordDescriptor(
        "test/record",
        [
            ("uint32", "value"),
        ],
    )

    del base.RESERVED_FIELDS["_extra"]

    RecordDescriptor.get_required_fields.cache_clear()
    _generate_record_class.cache_clear()
    TestRecordBase = RecordDescriptor(
        "test/record",
        [
            ("uint32", "value"),
        ],
    )

    packer = RecordPacker()
    r = TestRecordExtra(1, _extra=1337)

    assert r.value == 1
    assert r._extra == 1337

    data = packer.pack(r)
    packer.register(TestRecordBase)

    unpacked = packer.unpack(data)

    with pytest.raises(AttributeError):
        assert unpacked._extra

    assert unpacked.value == 1
    assert unpacked._version == 1


def test_no_version_field_regression() -> None:
    # Emulate old style record
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "value"),
        ],
    )
    packer.register(TestRecord)

    r = TestRecord(1)

    packed = r._pack()
    mod = (packed[0], packed[1][:-1])  # Strip version field
    rdata = packer.pack((RECORD_PACK_TYPE_RECORD, mod))
    data = packer.pack(msgpack.ExtType(RECORD_PACK_EXT_TYPE, rdata))

    with pytest.warns(RuntimeWarning) as record:
        unpacked = packer.unpack(data)

    assert len(record) == 1
    assert record[0].message.args[0].startswith("Got old style record with no version information")

    assert unpacked.value == 1
    assert unpacked._version == 1  # Version field implicitly added


def test_mixed_case_name() -> None:
    assert is_valid_field_name("Test")
    assert is_valid_field_name("test")
    assert is_valid_field_name("TEST")
    assert not is_valid_field_name("test[]")
    assert not is_valid_field_name("_test")

    TestRecord = RecordDescriptor(
        "Test/Record",
        [
            ("uint32", "Value"),
        ],
    )

    r = TestRecord(1)
    assert r.Value == 1


def test_multi_grouped_record_serialization(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "Test/Record",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )
    GeoRecord = RecordDescriptor(
        "geoip/country",
        [
            ("string", "country"),
            ("string", "city"),
        ],
    )
    ASNRecord = RecordDescriptor(
        "geoip/asn",
        [
            ("string", "asn"),
            ("string", "isp"),
        ],
    )

    with pytest.deprecated_call():
        test_rec = TestRecord("1.3.3.7")
    geo_rec = GeoRecord(country="Netherlands", city="Delft")

    grouped_rec = GroupedRecord("grouped/geoip", [test_rec, geo_rec])
    asn_rec = ASNRecord(asn="1337", isp="Cyberspace")
    record = GroupedRecord("grouped/geo/asn", [grouped_rec, asn_rec])

    assert record.ip == "1.3.3.7"
    assert record.country == "Netherlands"
    assert record.city == "Delft"
    assert record.asn == "1337"
    assert record.isp == "Cyberspace"

    writer = RecordWriter(tmp_path / "out.record")
    writer.write(record)
    writer.close()

    with pytest.deprecated_call():
        reader = RecordReader(tmp_path / "out.record")
        records = list(reader)
        assert len(records) == 1
        record = records[0]
        assert record.ip == "1.3.3.7"
        assert record.country == "Netherlands"
        assert record.city == "Delft"
        assert record.asn == "1337"
        assert record.isp == "Cyberspace"


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_ast_unicode_literals(PSelector: type[Selector | CompiledSelector]) -> None:
    TestRecord = RecordDescriptor("Test/Record", [])
    assert TestRecord() in PSelector("get_type('string literal') == get_type(u'hello')")
    assert TestRecord() in PSelector("get_type('not bytes') != get_type(b'hello')")


def test_grouped_replace() -> None:
    TestRecord = RecordDescriptor(
        "test/adapter",
        [
            ("uint32", "number"),
        ],
    )
    OtherRecord = RecordDescriptor(
        "test/other",
        [
            ("string", "other"),
        ],
    )

    # Constructing grouped record normally
    record = TestRecord(number=1)
    other_record = OtherRecord("foobar")
    grouped_record = GroupedRecord("grouped/original", [record, other_record])
    assert grouped_record._source is None
    assert grouped_record.number == 1
    assert grouped_record.other == "foobar"

    # Constructing grouped record normally (using a replaced record)
    replaced_record = record._replace(_source="newsource")
    grouped_record = GroupedRecord("grouped/replaced", [replaced_record, other_record])
    assert grouped_record._source == "newsource"
    assert grouped_record.number == 1
    assert grouped_record.other == "foobar"

    # Test GroupedRecord replace
    replaced_grouped_record = grouped_record._replace(number=100)
    assert replaced_grouped_record.number == 100
    assert replaced_grouped_record.other == "foobar"

    # Test with multiple replacements
    replaced_grouped_record = grouped_record._replace(number=200, other="a string", _source="testcase")
    assert replaced_grouped_record.number == 200
    assert replaced_grouped_record.other == "a string"
    assert replaced_grouped_record._source == "testcase"

    # Replacement with non existing field should raise a ValueError
    with pytest.raises(ValueError, match=".*Got unexpected field names:.*non_existing_field.*"):
        grouped_record._replace(number=100, other="changed", non_existing_field="oops")


def test_bytes_line_adapter(capsys: pytest.CaptureFixture) -> None:
    TestRecord = RecordDescriptor(
        "test/bytes_hex",
        [
            ("bytes", "data"),
        ],
    )

    with RecordWriter("line://") as writer:
        writer.write(TestRecord(b"hello world"))

    captured = capsys.readouterr()
    assert "data = b'hello world'" in captured.out


def test_is_stdout(tmp_path: pathlib.Path, capsysbinary: pytest.CaptureFixture) -> None:
    assert is_stdout(sys.stdout)
    assert is_stdout(sys.stdout.buffer)

    assert not is_stdout(sys.stderr)
    assert not is_stdout(sys.stderr.buffer)

    with (tmp_path / "test").open("w") as f:
        assert not is_stdout(f)

    with RecordWriter() as writer:
        assert is_stdout(writer.fp)

    out, err = capsysbinary.readouterr()
    assert out.startswith(b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n")

    with RecordWriter(tmp_path / "output.records") as writer:
        assert not is_stdout(writer.fp)

    with RecordWriter("csvfile://") as writer:
        assert is_stdout(writer.fp)

    with RecordWriter("line://") as writer:
        assert is_stdout(writer.fp)


def test_rdump_fieldtype_path_json(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("path", "path"),
        ],
    )

    # write the test records so rdump can read it
    record_path = tmp_path / "test.records"
    with RecordWriter(record_path) as writer:
        writer.write(
            TestRecord(
                path=fieldtypes.path.from_windows(r"c:\windows\system32"),
            )
        )
        writer.write(
            TestRecord(
                path=fieldtypes.path.from_posix("/root/.bash_history"),
            )
        )

    # rdump --jsonlines
    args = [
        "rdump",
        str(record_path),
        "--jsonlines",
    ]
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()

    assert process.returncode == 0
    assert stderr is None

    # strip _generated, _source, _classification from dictionary
    jsonlines = []
    for line in stdout.splitlines():
        jsondict = {k: v for k, v in json.loads(line).items() if not k.startswith("_")}
        jsonlines.append(jsondict)

    assert jsonlines == [
        {"path": "c:\\windows\\system32"},
        {"path": "/root/.bash_history"},
    ]


@pytest.mark.parametrize(
    "path_initializer",
    [
        pathlib.PureWindowsPath,
        fieldtypes.windows_path,
        fieldtypes.path.from_windows,
    ],
)
def test_windows_path_regression(path_initializer: Callable[[str], pathlib.PurePath]) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("path", "path"),
        ],
    )
    r = TestRecord(path=path_initializer("/c:/Windows/System32/drivers/null.sys"))
    assert str(r.path) == "\\c:\\Windows\\System32\\drivers\\null.sys"
    assert repr(r.path) == "'\\c:\\Windows\\System32\\drivers\\null.sys'"


@pytest.mark.parametrize(
    ("record_count", "count", "expected_count"),
    [
        (10, 10, 10),
        (0, 10, 0),
        (1, 10, 1),
        (5, 0, 5),  # --count 0 should be ignored
        (5, 1, 1),
        (5, 10, 5),
    ],
)
def test_rdump_count_list(
    tmp_path: pathlib.Path, capsysbinary: pytest.CaptureFixture, record_count: int, count: int, expected_count: int
) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
        ],
    )

    # write the test records so rdump can read it
    record_path = tmp_path / "test.records"
    with RecordWriter(record_path) as writer:
        for i in range(record_count):
            writer.write(TestRecord(count=i))

    # rdump --count <count>
    rdump.main([str(record_path), "--count", str(count)])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert len(captured.out.splitlines()) == expected_count

    # rdump --list --count <count>
    rdump.main([str(record_path), "--list", "--count", str(count)])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert f"Processed {expected_count} records".encode() in captured.out


def test_record_adapter_windows_path(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "text"),
        ],
    )
    path_records = tmp_path / "test.records"
    with RecordWriter(path_records) as writer:
        writer.write(TestRecord("foo"))
        writer.write(TestRecord("bar"))

    mock_reader = MagicMock(wraps=BytesIO(path_records.read_bytes()), spec=BytesIO)
    mock_reader.closed = False

    with patch.object(pathlib.Path, "open", autospec=True) as m:
        m.return_value = mock_reader
        adapter = RecordReader(r"c:\users\user\test.records")
        assert type(adapter).__name__ == "StreamReader"

        m.assert_called_once_with(pathlib.Path(r"c:\users\user\test.records"), "rb")
        assert [r.text for r in adapter] == ["foo", "bar"]

    with patch.object(pathlib.Path, "open", autospec=True) as m:
        m.return_value = MagicMock(spec=BytesIO)
        adapter = RecordWriter(r"c:\users\user\test.records")
        assert type(adapter).__name__ == "StreamWriter"
        m.assert_called_once_with(pathlib.Path(r"c:\users\user\test.records"), "wb")


def test_datetime_as_fieldname() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "datetime"),
        ],
    )
    TestRecord()


def test_string_surrogateescape_serialization(tmp_path: pathlib.Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "str_value"),
        ],
    )

    str_value = b"hello \xa7 world".decode(errors="surrogateescape")
    record = TestRecord(str_value=str_value)
    assert str_value == "hello \udca7 world"
    assert record.str_value == str_value

    with RecordWriter(tmp_path / "test.records") as writer:
        writer.write(record)

    with RecordReader(tmp_path / "test.records") as reader:
        record = next(iter(reader))
        assert str(record.str_value) == str_value
        assert record.str_value == str_value
        assert record.str_value.encode(errors="surrogateescape") == b"hello \xa7 world"


def test_fieldtype_typedlist_net_ipaddress() -> None:
    assert fieldtype("net.ipaddress[]")
    assert fieldtype("net.ipaddress[]").__type__ == fieldtypes.net.ipaddress
    assert issubclass(fieldtype("net.ipaddress[]"), list)
    assert issubclass(fieldtype("net.ipaddress[]"), fieldtypes.FieldType)


def test_record_reader_default_stdin(tmp_path: pathlib.Path) -> None:
    """RecordWriter should default to stdin if no path is given"""
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "text"),
        ],
    )

    # write some records
    records_path = tmp_path / "test.records"
    with RecordWriter(records_path) as writer:
        writer.write(TestRecord("foo"))

    # Test stdin
    with patch("sys.stdin", BytesIO(records_path.read_bytes())), RecordReader() as reader:
        for record in reader:
            assert record.text == "foo"


def test_record_writer_default_stdout(capsysbinary: pytest.CaptureFixture) -> None:
    """RecordWriter should default to stdout if no path is given"""
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "text"),
        ],
    )

    # write a record to stdout
    with RecordWriter() as writer:
        writer.write(TestRecord("foo"))

    stdout = capsysbinary.readouterr().out
    assert stdout.startswith(b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n")


def test_rdump_selected_fields(capsysbinary: pytest.CaptureFixture) -> None:
    """Test rdump regression where selected fields was not propagated properly to adapter."""

    # Pastebin record used for this test
    example_records_json_path = Path(__file__).parent.parent / "examples" / "records.json"

    # rdump --fields key,title,syntax --csv
    rdump.main([str(example_records_json_path), "--fields", "key,title,syntax", "--csv"])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert captured.out == b"key,title,syntax\r\nQ42eWSaF,A sample pastebin record,text\r\n"

    # rdump --fields key,title,syntax --csv
    rdump.main([str(example_records_json_path), "--fields", "key,title,syntax", "--csv-no-header"])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert captured.out == b"Q42eWSaF,A sample pastebin record,text\r\n"


if __name__ == "__main__":
    __import__("standalone_test").main(globals())
