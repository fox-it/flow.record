from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from flow.record import RecordDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record


def generate_records(count: int = 100) -> Iterator[Record]:
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


def generate_plain_records(count: int = 100) -> Iterator[Record]:
    TestRecord = RecordDescriptor(
        "test/adapter/plain",
        [
            ("uint32", "number"),
            ("datetime", "dt"),
        ],
    )

    for i in range(count):
        yield TestRecord(number=i, dt=datetime.datetime.now(datetime.timezone.utc))
