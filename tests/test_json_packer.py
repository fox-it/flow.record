import json
from datetime import datetime, timezone

import pytest

from flow.record import JsonRecordPacker, RecordDescriptor, fieldtypes
from flow.record.exceptions import RecordDescriptorNotFound


def test_record_in_record():
    packer = JsonRecordPacker()
    dt = datetime.now(timezone.utc)

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


def test_pack_path_fieldtype():
    packer = JsonRecordPacker()
    TestRecord = RecordDescriptor(
        "test/pack_path",
        [
            ("path", "path"),
        ],
    )

    r = TestRecord(path=fieldtypes.path.from_windows(r"c:\windows\system32"))
    assert json.loads(packer.pack(r))["path"] == "c:\\windows\\system32"

    r = TestRecord(path=fieldtypes.path.from_posix("/root/.bash_history"))
    assert json.loads(packer.pack(r))["path"] == "/root/.bash_history"


def test_record_descriptor_not_found():
    TestRecord = RecordDescriptor(
        "test/descriptor_not_found",
        [
            ("string", "foo"),
        ],
    )

    # pack a record into bytes
    packer = JsonRecordPacker()
    data = packer.pack(TestRecord(foo="bar"))
    assert isinstance(data, str)
    assert json.loads(data)["foo"] == "bar"

    # create a new packer and try to unpack the bytes
    packer = JsonRecordPacker()
    with pytest.raises(RecordDescriptorNotFound, match="No RecordDescriptor found for: .*test/descriptor_not_found"):
        packer.unpack(data)
