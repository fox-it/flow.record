import datetime

from flow.record import RecordDescriptor
from flow.record import iter_timestamped_records


def test_multi_timestamp():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ctime"),
            ("datetime", "atime"),
            ("string", "data"),
        ],
    )

    test_record = TestRecord(
        ctime=datetime.datetime(2020, 1, 1, 1, 1, 1),
        atime=datetime.datetime(2022, 11, 22, 13, 37, 37),
        data="test",
    )

    ts_records = list(iter_timestamped_records(test_record))

    for rec in ts_records:
        assert rec.ctime == datetime.datetime(2020, 1, 1, 1, 1, 1)
        assert rec.atime == datetime.datetime(2022, 11, 22, 13, 37, 37)
        assert rec.data == "test"

    assert ts_records[0].ts == datetime.datetime(2020, 1, 1, 1, 1, 1)
    assert ts_records[0].ts_description == "ctime"

    assert ts_records[1].ts == datetime.datetime(2022, 11, 22, 13, 37, 37)
    assert ts_records[1].ts_description == "atime"


def test_multi_timestamp_no_datetime():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "data"),
        ],
    )

    test_record = TestRecord(data="test")
    ts_records = list(iter_timestamped_records(test_record))
    assert len(ts_records) == 1
    assert ts_records[0].data == "test"


def test_multi_timestamp_single_datetime():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ctime"),
            ("string", "data"),
        ],
    )

    test_record = TestRecord(
        ctime=datetime.datetime(2020, 1, 1, 1, 1, 1),
        data="test",
    )
    ts_records = list(iter_timestamped_records(test_record))
    assert len(ts_records) == 1
    assert ts_records[0].ts == test_record.ctime
    assert ts_records[0].ts_description == "ctime"


def test_multi_timestamp_ts_fieldname():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ts"),
            ("string", "data"),
        ],
    )

    test_record = TestRecord(
        ts=datetime.datetime(2020, 1, 1, 1, 1, 1),
        data="test",
    )
    ts_records = list(iter_timestamped_records(test_record))
    assert len(ts_records) == 1
    assert ts_records[0].ts == test_record.ts
    assert ts_records[0].ts_description == "ts"


def test_multi_timestamp_timezone():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ts"),
            ("string", "data"),
        ],
    )

    correct_ts = datetime.datetime(2023, 12, 31, 13, 37, 1, 123456, tzinfo=datetime.timezone.utc)

    ts_notations = [
        correct_ts,
        "2023-12-31T13:37:01.123456Z",
    ]

    for i, ts_notation in enumerate(ts_notations):
        test_record = TestRecord(
            ts=ts_notation,
            data=f"record with timezone ({str(i)})",
        )
        ts_records = list(iter_timestamped_records(test_record))
        assert len(ts_records) == 1
        assert ts_records[0].ts == correct_ts
        assert ts_records[0].ts_description == "ts"
