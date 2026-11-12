from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.adapter.avro import AvroReader, AvroWriter, descriptor_to_schema
from flow.record.base import HAS_AVRO
from flow.record.fieldtypes import posix_path
from tests._utils import generate_plain_records

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from flow.record.base import Record


def generate_records(amount: int) -> Iterator[Record]:
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


def test_writing_reading_avrofile(tmp_path: Path) -> None:
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


def test_avrostream_filelike_object(tmp_path: Path) -> None:
    if not HAS_AVRO:
        pytest.skip("fastavro module not installed")
    avro_path = tmp_path / "test.avro"

    out = AvroWriter(avro_path)
    for rec in generate_records(100):
        out.write(rec)
    out.close()

    avro_io = BytesIO(avro_path.read_bytes())

    reader = RecordReader(fileobj=avro_io)

    #  The record reader should automatically have created an 'AvroReader' to handle the Avro Record Stream
    assert isinstance(reader, AvroReader)

    # Verify if selector worked and records are the same
    for index, rec in enumerate(reader):
        assert rec.name == f"record{index}"
        assert rec.foo == "bar"
        assert rec.bar == "baz"


def test_avro_adapter(tmpdir: Path) -> None:
    json_file = tmpdir.join("records.avro")
    record_adapter_path = f"avro://{json_file}"
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


def test_avro_adapter_contextmanager(tmpdir: Path) -> None:
    json_file = tmpdir.join("records.avro")
    record_adapter_path = f"avro://{json_file}"
    with RecordWriter(record_adapter_path) as writer:
        nr_records = 1337
        for record in generate_plain_records(nr_records):
            writer.write(record)

    nr_received_records = 0
    with RecordReader(record_adapter_path) as reader:
        for _ in reader:
            nr_received_records += 1

        assert nr_records == nr_received_records


def test_avro_path_field(tmp_path: Path) -> None:
    if not HAS_AVRO:
        pytest.skip("fastavro module not installed")

    UserRecord = RecordDescriptor(
        "test/user",
        [
            ("string", "name"),
            ("path", "home"),
        ],
    )
    avro_path = tmp_path / "users.avro"

    with AvroWriter(avro_path) as writer:
        writer.write(UserRecord(name="alice", home=posix_path("/home/alice")))
        writer.write(UserRecord(name="bob"))

    with AvroReader(avro_path) as reader:
        records = list(reader)

    assert records[0].name == "alice"
    assert records[0].home == "/home/alice"
    assert records[1].name == "bob"
    assert records[1].home is None


def test_avro_descriptor_to_schema_path() -> None:
    if not HAS_AVRO:
        pytest.skip("fastavro module not installed")

    desc = RecordDescriptor("test/user", [("path", "home")])
    schema = descriptor_to_schema(desc)
    assert schema["fields"][0]["type"] == ["string", "null"]


def test_avro_adapter_empty(tmpdir: Path) -> None:
    json_file = tmpdir.join("records.avro")
    record_adapter_path = f"avro://{json_file}"
    with RecordWriter(record_adapter_path):
        pass

    nr_received_records = 0
    with RecordReader(record_adapter_path) as reader:
        for _ in reader:
            nr_received_records += 1

        assert nr_received_records == 0
