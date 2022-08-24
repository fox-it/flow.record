import json
import datetime
from flow.record import RecordDescriptor, RecordWriter, RecordReader


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
        embedded = TestRecordEmbedded(datetime.datetime.utcnow())
        yield TestRecord(number=i, record=embedded)


def test_json_adapter(tmpdir):
    json_file = tmpdir.join("records.json")
    record_adapter_path = "jsonfile://{}".format(json_file)
    writer = RecordWriter(record_adapter_path)
    nr_records = 1337

    for record in generate_records(nr_records):
        writer.write(record)
    writer.flush()

    nr_received_records = 0
    reader = RecordReader(record_adapter_path)
    for record in reader:
        nr_received_records += 1

    assert nr_records == nr_received_records


def test_json_adapter_contextmanager(tmpdir):
    json_file = tmpdir.join("records.json")
    record_adapter_path = "jsonfile://{}".format(json_file)
    with RecordWriter(record_adapter_path) as writer:
        nr_records = 1337
        for record in generate_records(nr_records):
            writer.write(record)

    nr_received_records = 0
    with RecordReader(record_adapter_path) as reader:
        for record in reader:
            nr_received_records += 1

        assert nr_records == nr_received_records


def test_json_adapter_jsonlines(tmpdir):
    json_file = tmpdir.join("data.jsonl")

    items = [
        {"some_float": 1.5, "some_string": "hello world", "some_int": 1337, "some_bool": True},
        {"some_float": 2.7, "some_string": "goodbye world", "some_int": 12345, "some_bool": False},
    ]
    with open(json_file, "w") as fout:
        for row in items:
            fout.write(json.dumps(row) + "\n")

    record_adapter_path = "jsonfile://{}".format(json_file)
    reader = RecordReader(record_adapter_path)
    for index, record in enumerate(reader):
        assert record.some_float == items[index]["some_float"]
        assert record.some_string == items[index]["some_string"]
        assert record.some_int == items[index]["some_int"]
        assert record.some_bool == items[index]["some_bool"]
