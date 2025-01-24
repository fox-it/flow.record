from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from flow.record import RecordDescriptor, RecordReader
from flow.record.adapter.avro import AvroReader, AvroWriter
from flow.record.base import HAS_AVRO

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
