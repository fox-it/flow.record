import pytest
import codecs
import os
import datetime
import sys

import msgpack

from flow.record import (
    base,
    whitelist,
    fieldtypes,
    Record,
    GroupedRecord,
    RecordDescriptor,
    RecordPacker,
    RECORD_VERSION,
    RecordReader,
    RecordWriter,
)
from flow.record.base import is_valid_field_name
from flow.record.packer import RECORD_PACK_EXT_TYPE, RECORD_PACK_TYPE_RECORD
from flow.record.selector import Selector, CompiledSelector


def test_datetime_serialization():
    packer = RecordPacker()

    now = datetime.datetime.utcnow()

    for tz in ["UTC", "Europe/Amsterdam"]:
        os.environ["TZ"] = tz

        desc = """
        test/datetime
        datetime datetime;
        """
        descriptor = RecordDescriptor(desc)

        record = descriptor.recordType(datetime=now)
        data = packer.pack(record)
        r = packer.unpack(data)

        assert r.datetime == now


def test_long_int_serialization():
    packer = RecordPacker()

    desc = """
    test/long_types
    varint long_type;
    varint int_type;
    varint long_type_neg;
    varint int_type_neg;
    varint max_int_as_long;
    """
    long_types = RecordDescriptor(desc)

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


def test_unicode_serialization():
    packer = RecordPacker()

    desc = """
    test/unicode
    string text;
    """
    descriptor = RecordDescriptor(desc)

    puny_domains = [b"xn--s7y.co", b"xn--80ak6aa92e.com", b"xn--pple-43d.com"]

    for p in puny_domains:
        domain = codecs.decode(p, "idna")
        record = descriptor.recordType(text=domain)
        d = packer.pack(record)
        record2 = packer.unpack(d)

        assert record.text == record2.text
        assert record.text == domain


def test_pack_long_int_serialization():
    packer = RecordPacker()
    # test if 'long int' that fit in the 'int' type would be packed as int internally

    max_neg_int = -0x8000000000000000
    d = packer.pack([1234, 123456, max_neg_int, sys.maxsize])
    assert (
        d
        == b"\x94\xcd\x04\xd2\xce\x00\x01\xe2@\xd3\x80\x00\x00\x00\x00\x00\x00\x00\xcf\x7f\xff\xff\xff\xff\xff\xff\xff"
    )  # noqa: E501


def test_non_existing_field():
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


def test_set_field_type():
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

    with pytest.raises(ValueError):
        r.value = "lalala"
    r.value = 2

    r = TestRecord()
    assert r.value is None
    r.value = 1234
    assert r.value == 1234
    with pytest.raises(TypeError):
        r.value = [1, 2, 3, 4, 5]


def test_packer_unpacker_none_values():
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


def test_fieldname_regression():
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


def test_version_field_regression():
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


def test_reserved_field_count_regression():
    del base.RESERVED_FIELDS["_version"]
    base.RESERVED_FIELDS["_extra"] = "varint"
    base.RESERVED_FIELDS["_version"] = "varint"

    TestRecordExtra = RecordDescriptor(
        "test/record",
        [
            ("uint32", "value"),
        ],
    )

    del base.RESERVED_FIELDS["_extra"]

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
        unpacked._extra

    assert unpacked.value == 1
    assert unpacked._version == 1


def test_no_version_field_regression():
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


def test_mixed_case_name():
    assert is_valid_field_name("Test")
    assert is_valid_field_name("test")
    assert is_valid_field_name("TEST")

    TestRecord = RecordDescriptor(
        "Test/Record",
        [
            ("uint32", "Value"),
        ],
    )

    r = TestRecord(1)
    assert r.Value == 1


def test_multi_grouped_record_serialization(tmp_path):
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
def test_ast_unicode_literals(PSelector):
    TestRecord = RecordDescriptor("Test/Record", [])
    assert TestRecord() in PSelector("get_type('string literal') == get_type(u'hello')")
    assert TestRecord() in PSelector("get_type('not bytes') != get_type(b'hello')")


def test_grouped_replace():
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
    with pytest.raises(ValueError) as excinfo:
        grouped_record._replace(number=100, other="changed", non_existing_field="oops")
    excinfo.match(".*Got unexpected field names:.*non_existing_field.*")


if __name__ == "__main__":
    __import__("standalone_test").main(globals())
