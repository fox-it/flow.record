from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flow.record import RecordDescriptor, iter_timestamped_records
from flow.record.base import merge_record_descriptors

UTC = timezone.utc


def test_multi_timestamp() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ctime"),
            ("datetime", "atime"),
            ("string", "data"),
        ],
    )

    test_record = TestRecord(
        ctime=datetime(2020, 1, 1, 1, 1, 1),  # noqa: DTZ001
        atime=datetime(2022, 11, 22, 13, 37, 37),  # noqa: DTZ001
        data="test",
    )

    ts_records = list(iter_timestamped_records(test_record))

    for rec in ts_records:
        assert rec.ctime == datetime(2020, 1, 1, 1, 1, 1, tzinfo=UTC)
        assert rec.atime == datetime(2022, 11, 22, 13, 37, 37, tzinfo=UTC)
        assert rec.data == "test"

    assert ts_records[0].ts == datetime(2020, 1, 1, 1, 1, 1, tzinfo=UTC)
    assert ts_records[0].ts_description == "ctime"

    assert ts_records[1].ts == datetime(2022, 11, 22, 13, 37, 37, tzinfo=UTC)
    assert ts_records[1].ts_description == "atime"


def test_multi_timestamp_no_datetime() -> None:
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


def test_multi_timestamp_single_datetime() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ctime"),
            ("string", "data"),
        ],
    )

    test_record = TestRecord(
        ctime=datetime(2020, 1, 1, 1, 1, 1),  # noqa: DTZ001
        data="test",
    )
    ts_records = list(iter_timestamped_records(test_record))
    assert len(ts_records) == 1
    assert ts_records[0].ts == test_record.ctime
    assert ts_records[0].ts_description == "ctime"


def test_multi_timestamp_ts_fieldname() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ts"),
            ("string", "data"),
        ],
    )

    test_record = TestRecord(
        ts=datetime(2020, 1, 1, 1, 1, 1),  # noqa: DTZ001
        data="test",
    )
    ts_records = list(iter_timestamped_records(test_record))
    assert len(ts_records) == 1
    assert ts_records[0].ts == test_record.ts
    assert ts_records[0].ts_description == "ts"


def test_multi_timestamp_timezone() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ts"),
            ("string", "data"),
        ],
    )

    correct_ts = datetime(2023, 12, 31, 13, 37, 1, 123456, tzinfo=UTC)

    ts_notations = [
        correct_ts,
        "2023-12-31T13:37:01.123456Z",
    ]

    for i, ts_notation in enumerate(ts_notations):
        test_record = TestRecord(
            ts=ts_notation,
            data=f"record with timezone ({i!s})",
        )
        ts_records = list(iter_timestamped_records(test_record))
        assert len(ts_records) == 1
        assert ts_records[0].ts == correct_ts
        assert ts_records[0].ts_description == "ts"


def test_multi_timestamp_descriptor_cache() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ctime"),
            ("datetime", "atime"),
            ("varint", "count"),
            ("string", "data"),
        ],
    )

    merge_record_descriptors.cache_clear()
    for i in range(10):
        test_record = TestRecord(
            ctime=datetime.now(UTC) + timedelta(hours=69),
            atime=datetime.now(UTC) + timedelta(hours=420),
            count=i,
            data=f"test {i}",
        )
        for record in iter_timestamped_records(test_record):
            assert record.data == f"test {i}"
            assert record.count == i
            assert record.ctime == test_record.ctime
            assert record.atime == test_record.atime
            assert hasattr(record, "ts")
            assert hasattr(record, "ts_description")
            tsfield = record.ts_description
            assert record.ts == getattr(test_record, tsfield)

    cache_info = merge_record_descriptors.cache_info()
    assert cache_info.misses == 2
    assert cache_info.hits == 18
