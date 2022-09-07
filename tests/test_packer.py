import datetime

import pytest

from flow.record import fieldtypes
from flow.record import RecordDescriptor
from flow.record import RecordPacker
from flow.record.packer import RECORD_PACK_EXT_TYPE
from flow.record.fieldtypes import uri


def test_uri_packing():
    packer = RecordPacker()

    TestRecord = RecordDescriptor(
        "test/uri",
        [
            ("uri", "path"),
        ],
    )

    # construct with an url
    record = TestRecord("http://www.google.com/evil.bin")
    data = packer.pack(record)
    record = packer.unpack(data)
    assert record.path == "http://www.google.com/evil.bin"
    assert record.path.filename == "evil.bin"
    assert record.path.dirname == "/"

    # construct from uri() -> for windows=True
    with pytest.warns(DeprecationWarning):
        path = uri.from_windows(r"c:\Program Files\Fox-IT\flow is awesome.exe")
    record = TestRecord(path)
    data = packer.pack(record)
    record = packer.unpack(data)
    assert record.path == "c:/Program Files/Fox-IT/flow is awesome.exe"
    assert record.path.filename == "flow is awesome.exe"
    assert record.path.dirname == "/Program Files/Fox-IT"

    # construct using uri.from_windows()
    with pytest.warns(DeprecationWarning):
        path = uri.from_windows(r"c:\Users\Hello World\foo.bar.exe")
    record = TestRecord(path)
    data = packer.pack(record)
    record = packer.unpack(data)
    assert record.path == "c:/Users/Hello World/foo.bar.exe"
    assert record.path.filename == "foo.bar.exe"
    assert record.path.dirname == "/Users/Hello World"


def test_typedlist_packer():
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/typedlist",
        [
            ("string[]", "string_value"),
            ("uint32[]", "uint32_value"),
            ("uri[]", "uri_value"),
        ],
    )

    r1 = TestRecord(["a", "b", "c"], [1, 2, 3], ["/etc/passwd", "/etc/shadow"])
    data = packer.pack(r1)
    r2 = packer.unpack(data)

    assert len(r1.string_value) == 3
    assert len(r1.uint32_value) == 3
    assert len(r1.uri_value) == 2
    assert r1.string_value[2] == "c"
    assert r1.uint32_value[1] == 2
    assert all([isinstance(v, uri) for v in r1.uri_value])
    assert r1.uri_value[1].filename == "shadow"

    assert len(r2.string_value) == 3
    assert len(r2.uint32_value) == 3
    assert len(r2.uri_value) == 2
    assert r2.string_value[2] == "c"
    assert r2.uint32_value[1] == 2
    assert all([isinstance(v, uri) for v in r2.uri_value])
    assert r2.uri_value[1].filename == "shadow"


def test_dictlist_packer():
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/dictlist",
        [
            ("dictlist", "hits"),
        ],
    )

    r1 = TestRecord([{"a": 1, "b": 2}, {"a": 3, "b": 4}])
    data = packer.pack(r1)
    r2 = packer.unpack(data)

    assert len(r1.hits) == 2
    assert r1.hits == [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    assert r1.hits[0]["a"] == 1
    assert r1.hits[0]["b"] == 2
    assert r1.hits[1]["a"] == 3
    assert r1.hits[1]["b"] == 4

    assert len(r2.hits) == 2
    assert r2.hits == [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    assert r2.hits[0]["a"] == 1
    assert r2.hits[0]["b"] == 2
    assert r2.hits[1]["a"] == 3
    assert r2.hits[1]["b"] == 4


def test_dynamic_packer():
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/dynamic",
        [
            ("dynamic", "value"),
        ],
    )

    t = TestRecord(123)
    data = packer.pack(t)
    r = packer.unpack(data)

    assert r.value == 123
    assert isinstance(r.value, fieldtypes.varint)

    t = TestRecord(b"bytes")
    data = packer.pack(t)
    r = packer.unpack(data)

    assert r.value == b"bytes"
    assert isinstance(r.value, fieldtypes.bytes)

    t = TestRecord("string")
    data = packer.pack(t)
    r = packer.unpack(data)

    assert r.value == "string"
    assert isinstance(r.value, fieldtypes.string)

    t = TestRecord(True)
    data = packer.pack(t)
    r = packer.unpack(data)

    assert r.value
    assert isinstance(r.value, fieldtypes.boolean)

    t = TestRecord([1, True, b"b", "u"])
    data = packer.pack(t)
    r = packer.unpack(data)

    assert r.value == [1, True, b"b", "u"]
    assert isinstance(r.value, fieldtypes.stringlist)

    now = datetime.datetime.utcnow()
    t = TestRecord(now)
    data = packer.pack(t)
    r = packer.unpack(data)

    assert r.value == now
    assert isinstance(r.value, fieldtypes.datetime)


def test_pack_record_desc():
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/pack",
        [
            ("string", "a"),
        ],
    )
    ext_type = packer.pack_obj(TestRecord)
    assert ext_type.code == RECORD_PACK_EXT_TYPE
    assert ext_type.data == b"\x92\x02\x92\xa9test/pack\x91\x92\xa6string\xa1a"
    desc = packer.unpack_obj(ext_type.code, ext_type.data)
    assert desc.name == TestRecord.name
    assert desc.fields.keys() == TestRecord.fields.keys()
    assert desc._pack() == TestRecord._pack()


def test_pack_digest():
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/digest",
        [
            ("digest", "digest"),
        ],
    )
    record = TestRecord(("d41d8cd98f00b204e9800998ecf8427e", None, None))
    data = packer.pack(record)
    record = packer.unpack(data)
    assert record.digest.md5 == "d41d8cd98f00b204e9800998ecf8427e"
    assert record.digest.sha1 is None
    assert record.digest.sha256 is None


def test_record_in_record():
    packer = RecordPacker()
    dt = datetime.datetime.utcnow()

    RecordA = RecordDescriptor(
        "test/record_a",
        [
            ("datetime", "some_dt"),
        ],
    )
    RecordB = RecordDescriptor(
        "test/record_b",
        [
            ("record", "record"),
            ("datetime", "some_dt"),
        ],
    )

    record_a = RecordA(dt)
    record_b = RecordB(record_a, dt)

    data_record_b = packer.pack(record_b)
    record_b_unpacked = packer.unpack(data_record_b)

    assert record_b == record_b_unpacked
    assert record_a == record_b_unpacked.record


def test_record_array():
    packer = RecordPacker()

    EmbeddedRecord = RecordDescriptor(
        "test/record_a",
        [
            ("string", "some_field"),
        ],
    )
    ParentRecord = RecordDescriptor(
        "test/record_b",
        [
            ("record[]", "subrecords"),
        ],
    )

    parent = ParentRecord()
    for i in range(3):
        emb_record = EmbeddedRecord(some_field="embedded record {}".format(i))
        parent.subrecords.append(emb_record)

    data_record_parent = packer.pack(parent)
    parent_unpacked = packer.unpack(data_record_parent)

    assert parent == parent_unpacked
