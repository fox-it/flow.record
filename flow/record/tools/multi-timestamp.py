from flow.record import RecordReader, RecordWriter, RecordDescriptor, extend_record

TimestampRecord = RecordDescriptor(
    "record/timestamp",
    [
        ("datetime", "ts"),
        ("string", "ts_description"),
    ],
)

with RecordReader() as reader, RecordWriter() as writer:
    for record in reader:
        # get all `datetime` fields. (excluding _generated).
        dt_fields = record._desc.getfields("datetime")

        # no `datetime` fields found, just output original record
        if not dt_fields:
            writer.write(record)
            continue

        # output a new record for each `datetime` field assigned as `ts`.
        record_name = record._desc.name
        for field in dt_fields:
            ts_record = TimestampRecord(getattr(record, field.name), field.name)
            # we extend `ts_record` with original `record` so TSRecord info goes first.
            record = extend_record(ts_record, [record], name=record_name)
            writer.write(record)
