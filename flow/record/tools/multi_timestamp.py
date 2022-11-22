# Python imports
import sys

from typing import Iterator

# Flow imports
from flow.record.utils import catch_sigpipe
from flow.record import (
    Record,
    RecordDescriptor,
    RecordReader,
    RecordWriter,
    extend_record,
)


TimestampRecord = RecordDescriptor(
    "record/timestamp",
    [
        ("datetime", "ts"),
        ("string", "ts_description"),
    ],
)


def iter_timestamped_records(record: Record) -> Iterator[Record]:
    """Yields timestamped annotated records for each `datetime` fieldtype in `record`.
    If `record` does not have any `datetime` fields the original record is returned.

    Args:
        record: Record to add timestamp fields for.

    Yields:
        Record annotated with `ts` and `ts_description` fields for each `datetime` fieldtype.
    """
    # get all `datetime` fields. (excluding _generated).
    dt_fields = record._desc.getfields("datetime")
    if not dt_fields:
        yield record
        return

    # yield a new record for each `datetime` field assigned as `ts`.
    record_name = record._desc.name
    for field in dt_fields:
        ts_record = TimestampRecord(getattr(record, field.name), field.name)
        # we extend `ts_record` with original `record` so TSRecord info goes first.
        record = extend_record(ts_record, [record], name=record_name)
        yield record


@catch_sigpipe
def main():
    with RecordReader() as reader, RecordWriter() as writer:
        for record in reader:
            for record in iter_timestamped_records(record):
                writer.write(record)


if __name__ == "__main__":
    sys.exit(main())
