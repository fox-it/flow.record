from flow.record import RecordReader, RecordWriter

from ._utils import generate_plain_records


def test_avro_adapter(tmpdir):
    json_file = tmpdir.join("records.avro")
    record_adapter_path = "avro://{}".format(json_file)
    writer = RecordWriter(record_adapter_path)
    nr_records = 1337

    for record in generate_plain_records(nr_records):
        writer.write(record)
    writer.flush()

    nr_received_records = 0
    reader = RecordReader(record_adapter_path)
    for _ in reader:
        nr_received_records += 1

    assert nr_records == nr_received_records


def test_avro_adapter_contextmanager(tmpdir):
    json_file = tmpdir.join("records.avro")
    record_adapter_path = "avro://{}".format(json_file)
    with RecordWriter(record_adapter_path) as writer:
        nr_records = 1337
        for record in generate_plain_records(nr_records):
            writer.write(record)

    nr_received_records = 0
    with RecordReader(record_adapter_path) as reader:
        for _ in reader:
            nr_received_records += 1

        assert nr_records == nr_received_records


def test_avro_adapter_empty(tmpdir):
    json_file = tmpdir.join("records.avro")
    record_adapter_path = "avro://{}".format(json_file)
    with RecordWriter(record_adapter_path):
        pass

    nr_received_records = 0
    with RecordReader(record_adapter_path) as reader:
        for _ in reader:
            nr_received_records += 1

        assert nr_received_records == 0
