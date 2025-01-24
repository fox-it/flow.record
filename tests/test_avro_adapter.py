from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record import RecordReader, RecordWriter

from ._utils import generate_plain_records

if TYPE_CHECKING:
    from pathlib import Path


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
