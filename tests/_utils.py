import datetime

from flow.record import RecordDescriptor


def generate_records(count=100):
    TestRecordEmbedded = RecordDescriptor(
        "test/embedded_record",
        [
            ("datetime", "dt"),
        ],
    )
    TestRecord = RecordDescriptor(
        "test/adapter",
        [
            ("uint32", "number"),
            ("record", "record"),
        ],
    )

    for i in range(count):
        embedded = TestRecordEmbedded(datetime.datetime.now(datetime.timezone.utc))
        yield TestRecord(number=i, record=embedded)


def generate_plain_records(count=100):
    TestRecord = RecordDescriptor(
        "test/adapter/plain",
        [
            ("uint32", "number"),
            ("datetime", "dt"),
        ],
    )

    for i in range(count):
        yield TestRecord(number=i, dt=datetime.datetime.now(datetime.timezone.utc))
