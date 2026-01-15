from pathlib import Path

import pytest

from flow.record import RecordDescriptor
from flow.record.adapter.arrow import ArrowReader, ArrowWriter
from tests._utils import generate_plain_records


@pytest.mark.parametrize("compression", ["none", "lz4", "zstd"])
def test_arrow_adapter_roundtrip(tmp_path: Path, compression: str) -> None:
    """Test writing and reading records using Arrow adapter."""

    records = list(generate_plain_records(count=100))
    output_path = tmp_path / f"test_roundtrip_{compression}.arrow"

    with ArrowWriter(output_path, compression=compression) as writer:
        for record in records:
            writer.write(record)

    with ArrowReader(output_path) as reader:
        read_records = list(reader)

    assert len(read_records) == len(records)
    for original, read in zip(records, read_records, strict=False):
        assert original._asdict() == read._asdict()
        assert original == read
        assert original._desc == read._desc


def test_arrow_stream_with_multiple_descriptors(tmp_path: Path) -> None:
    """Test writing and reading records with multiple descriptors using Arrow adapter."""

    MovieRecord = RecordDescriptor("movie/record", [("string", "title"), ("uint16", "year")])
    ActorRecord = RecordDescriptor("actor/record", [("string", "name"), ("uint16", "birth_year")])

    records = []
    records.append(MovieRecord("Inception", 2010))
    records.append(ActorRecord("Leonardo DiCaprio", 1974))
    records.append(MovieRecord("The Matrix", 1999))
    records.append(ActorRecord("Keanu Reeves", 1964))
    records.append(MovieRecord("Interstellar", 2014))
    records.append(ActorRecord("Matthew McConaughey", 1969))

    with ArrowWriter(tmp_path / "movies_and_actors.arrow") as writer:
        for record in records:
            writer.write(record)

    with ArrowReader(tmp_path / "movies_and_actors.arrow") as reader:
        read_records = list(reader)

    assert len(read_records) == len(records)
    for original, read in zip(records, read_records, strict=False):
        assert original._asdict() == read._asdict()
        assert original == read
        assert original._desc == read._desc
