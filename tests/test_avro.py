import pytest

try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO

from flow.record import RecordDescriptor, RecordReader
from flow.record.adapter.avro import AvroReader, AvroWriter
from flow.record.base import HAS_AVRO


def generate_records(amount):
    TestRecordWithFooBar = RecordDescriptor(
        "test/record",
        [
            ("string", "name"),
            ("string", "foo"),
            ("string", "bar"),
        ],
    )
    for i in range(amount):
        yield TestRecordWithFooBar(name=f"record{i}", foo="bar", bar="baz")


def test_writing_reading_avrofile(tmp_path):
    if not HAS_AVRO:
        pytest.skip("fastavro module not installed")
    avro_path = tmp_path / "test.avro"

    out = AvroWriter(avro_path)
    for rec in generate_records(100):
        out.write(rec)
    out.close()

    reader = AvroReader(avro_path)
    for index, rec in enumerate(reader):
        assert rec.name == f"record{index}"
        assert rec.foo == "bar"
        assert rec.bar == "baz"


def test_avrostream_filelike_object(tmp_path):
    if not HAS_AVRO:
        pytest.skip("fastavro module not installed")
    avro_path = tmp_path / "test.avro"

    out = AvroWriter(avro_path)
    for rec in generate_records(100):
        out.write(rec)
    out.close()

    with open(avro_path, "rb") as avro_file:
        avro_buffer = avro_file.read()

    avro_io = StringIO(avro_buffer)

    reader = RecordReader(avro_io)

    #  The record reader should automatically have created an 'AvroReader' to handle the Avro Record Stream
    assert isinstance(reader, AvroReader)

    # Verify if selector worked and records are the same
    for index, rec in enumerate(reader):
        assert rec.name == f"record{index}"
        assert rec.foo == "bar"
        assert rec.bar == "baz"
