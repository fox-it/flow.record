from __future__ import annotations

import hashlib
import struct

import pytest

from flow.record import RecordDescriptor, RecordField
from flow.record.exceptions import RecordDescriptorError


def test_record_descriptor() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
            ("varint", "status"),
        ],
    )

    # Get fields of type string
    fields = TestRecord.getfields("string")
    assert isinstance(fields, list)
    assert len(fields) == 2
    assert isinstance(fields[0], RecordField)
    assert fields[0].typename == "string"
    assert fields[0].name == "url"

    # Get fields as tuples
    fields = TestRecord.get_field_tuples()
    assert isinstance(fields, tuple)
    assert len(fields) == 3
    assert isinstance(fields[0], tuple)
    assert fields[0][0] == "string"
    assert fields[0][1] == "url"


def test_record_descriptor_clone() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
            ("varint", "status"),
        ],
    )

    # Clone record descriptor
    with pytest.deprecated_call():
        OtherRecord = RecordDescriptor("other/record", TestRecord)

    assert TestRecord.name == "test/record"
    assert OtherRecord.name == "other/record"
    assert TestRecord.descriptor_hash != OtherRecord.descriptor_hash
    assert TestRecord.get_field_tuples() == OtherRecord.get_field_tuples()


def test_record_descriptor_extend() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
        ],
    )

    # Add field
    ExtendedRecord = TestRecord.extend([("varint", "status")])

    assert TestRecord.name == "test/record"
    assert ExtendedRecord.name == "test/record"
    assert TestRecord.descriptor_hash != ExtendedRecord.descriptor_hash
    assert len(TestRecord.get_field_tuples()) == 2
    assert len(ExtendedRecord.get_field_tuples()) == 3


def test_record_descriptor_hash_cache() -> None:
    # Get initial cache stats
    TestRecord1 = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
        ],
    )
    assert TestRecord1.identifier == ("test/record", 2149661789)
    info = RecordDescriptor.calc_descriptor_hash.cache_info()

    # Create same descriptor, check cache hit increase
    TestRecord2 = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
        ],
    )
    assert TestRecord2.identifier == ("test/record", 2149661789)
    info2 = RecordDescriptor.calc_descriptor_hash.cache_info()
    assert info2.hits == info.hits + 1
    assert info.misses == info2.misses
    assert TestRecord1.descriptor_hash == TestRecord2.descriptor_hash

    # Create different descriptor, check for cache miss increase
    TestRecord3 = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
            ("boolean", "test"),
        ],
    )
    assert TestRecord3.identifier == ("test/record", 1878143470)
    info3 = RecordDescriptor.calc_descriptor_hash.cache_info()
    assert info2.hits == info.hits + 1
    assert info3.misses == info.misses + 1
    assert TestRecord2.descriptor_hash != TestRecord3.descriptor_hash


def test_record_descriptor_hashing() -> None:
    """Test if hashing is still consistent to keep compatibility"""
    TestRecord = RecordDescriptor(
        "test/hash",
        [
            ("boolean", "one"),
            ("string", "two"),
        ],
    )

    # known good values from flow.record version 1.4.1
    desc_hash = 1395243447
    desc_bytes = b"test/hashonebooleantwostring"

    # calculate
    hash_digest = struct.unpack(">L", hashlib.sha256(desc_bytes).digest()[:4])[0]
    assert desc_hash == hash_digest

    # verify current implementation
    assert TestRecord.descriptor_hash == hash_digest


def test_record_descriptor_hash_eq() -> None:
    """Tests __hash__() on RecordDescriptor"""
    TestRecordSame1 = RecordDescriptor(
        "test/same",
        [
            ("boolean", "one"),
            ("string", "two"),
        ],
    )

    TestRecordSame2 = RecordDescriptor(
        "test/same",
        [
            ("boolean", "one"),
            ("string", "two"),
        ],
    )

    TestRecordDifferentName = RecordDescriptor(
        "test/different",
        [
            ("boolean", "one"),
            ("string", "two"),
        ],
    )

    TestRecordDifferentFields = RecordDescriptor(
        "test/different",
        [
            ("varint", "one"),
            ("float", "two"),
        ],
    )

    # __hash__
    assert hash(TestRecordSame1) == hash(TestRecordSame2)
    assert hash(TestRecordSame1) != hash(TestRecordDifferentName)

    # __eq__
    assert TestRecordSame1 == TestRecordSame2
    assert TestRecordSame1 != TestRecordDifferentName
    assert TestRecordDifferentName != TestRecordDifferentFields


def test_record_descriptor_empty_fields() -> None:
    TestRecord = RecordDescriptor("test/empty", [])
    assert TestRecord()


def test_record_descriptor_empty_name() -> None:
    with pytest.raises(RecordDescriptorError, match="Record name is required"):
        RecordDescriptor(None, [])

    with pytest.raises(RecordDescriptorError, match="Record name is required"):
        RecordDescriptor("", [])
