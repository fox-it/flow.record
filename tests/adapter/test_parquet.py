from hashlib import md5, sha1, sha256
from pathlib import Path

import pytest

from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.adapter.parquet import ParquetReader, ParquetWriter
from tests._utils import generate_plain_records


def test_parquet_adapter_roundtrip(tmp_path: Path) -> None:
    """Test writing and reading records using Parquet adapter."""
    TestRecord = RecordDescriptor(
        name="TestRecord",
        fields=[
            ("string", "name"),
            ("uint16", "age"),
            ("filesize", "file_size"),
            ("varint", "count"),
            ("digest", "hash"),
            ("path", "file_path"),
        ],
    )

    digest_value = (md5(b"test").hexdigest(), sha1(b"test").hexdigest(), sha256(b"test").hexdigest())

    records = [
        TestRecord("Alice", 30, 123456789, 1000, digest_value, "/home/alice"),
        TestRecord("Bob", 25, 987654321, 2000, digest_value, "/home/bob"),
    ]

    # write records to Parquet file
    with ParquetWriter(tmp_path / "test.parquet") as writer:
        for record in records:
            writer.write(record)

    # read records back from Parquet file
    with ParquetReader(tmp_path / "test.parquet") as reader:
        read_records = list(reader)

    # verify that the read records match the original records
    assert len(read_records) == len(records)
    for original, read in zip(records, read_records, strict=False):
        assert original._asdict() == read._asdict()
        assert original == read
        assert original._desc == read._desc


@pytest.mark.parametrize("compression", ["none", "snappy", "gzip", "brotli", "lz4", "zstd"])
def test_parquet_compression(tmp_path: Path, compression: str) -> None:
    """Test Parquet writing and reading with different compression algorithms."""
    parq_path = tmp_path / "compressed.parquet"

    # write with specified compression
    with RecordWriter(f"parquet://{parq_path}?compression={compression}") as writer:
        for record in generate_plain_records(count=100):
            writer.write(record)

    # read back and verify
    with RecordReader(f"parquet://{parq_path}") as reader:
        records = list(reader)
    assert len(records) == 100


@pytest.mark.parametrize("compression", ["none", "snappy", "gzip", "brotli", "lz4", "zstd"])
@pytest.mark.parametrize("extension", [".parquet", ".parq", ".pq"])
def test_parquet_extension_writing(tmp_path: Path, extension: str, compression: str) -> None:
    """Test that RecordWriter can infer Parquet format from file extension."""
    parq_path = tmp_path / f"data{extension}"

    # write using a RecordWriter using a path with a parquet like extension
    with RecordWriter(parq_path) as writer:
        assert isinstance(writer, ParquetWriter)
        for record in generate_plain_records(count=50):
            writer.write(record)

    # test if we get a ParquetReader based on the extension
    with ParquetReader(parq_path) as reader:
        assert isinstance(reader, ParquetReader)
        records = list(reader)
    assert len(records) == 50


@pytest.mark.parametrize("extension", [".parquet", ".parq", ".pq"])
def test_parquet_extension_reading(tmp_path: Path, extension: str) -> None:
    """Test that RecordReader infers ParquetReader from file extension."""
    parq_path = tmp_path / f"data{extension}"

    # write using a ParquetWriter
    with ParquetWriter(parq_path) as writer:
        for record in generate_plain_records(count=50):
            writer.write(record)

    # test if we get a ParquetReader based on the extension
    with RecordReader(parq_path) as reader:
        assert isinstance(reader, ParquetReader)
        records = list(reader)
    assert len(records) == 50


def test_parquet_invalid_compression(tmp_path: Path) -> None:
    """Test that an invalid compression algorithm raises a ValueError."""
    parq_path = tmp_path / "invalid_compression.parquet"

    with RecordWriter(f"parquet://{parq_path}?compression=invalid_algo") as writer:
        for record in generate_plain_records(count=10):
            with pytest.raises(Exception, match="Unsupported compression: invalid_algo"):
                writer.write(record)


def test_parquet_missing_file(tmp_path: Path) -> None:
    """Test that attempting to read a non-existent Parquet file raises FileNotFoundError."""
    parq_path = tmp_path / "non_existent.parquet"

    with pytest.raises(FileNotFoundError), ParquetReader(parq_path) as reader:
        list(reader)


def test_parquet_empty_file(tmp_path: Path) -> None:
    """Test that reading an empty Parquet file raises an appropriate error."""
    parq_path = tmp_path / "0_byte_file.parquet"
    parq_path.touch()  # create an empty file

    with pytest.raises(Exception, match="Parquet file size is 0 bytes"), ParquetReader(parq_path) as reader:
        list(reader)


def test_parquet_zero_records(tmp_path: Path) -> None:
    """Test writing a Parquet file with zero records."""
    parq_path = tmp_path / "zero_records.parquet"

    with ParquetWriter(parq_path) as _writer:
        pass  # do not write any records

    # the above actually does not create a Parquet file as there were no records and no schema.
    assert not parq_path.exists(), "Parquet file should not be created when no records are written."


def test_read_iris_dataset_parquet(tmp_path: Path) -> None:
    """Test reading a sample Parquet file containing the Iris dataset.

    Dataset created using DuckDB with the following commands:

    .. code-block:: sql

        -- Load directly from the UCI repository
        CREATE TABLE iris AS
        SELECT * FROM read_csv_auto('https://archive.ics.uci.edu/ml/machine-learning-databases/iris/iris.data',
            header=false,
            columns={'sepal.length': 'DOUBLE', 'sepal.width': 'DOUBLE',
                    'petal.length': 'DOUBLE', 'petal.width': 'DOUBLE', 'species': 'VARCHAR'});

        -- Save as parquet with ZSTD compression
        COPY iris TO 'iris_zstd.parquet' (FORMAT PARQUET, COMPRESSION 'ZSTD', COMPRESSION_LEVEL 9);

    """
    iris_parquet_path = Path(__file__).parent.parent / "_data" / "iris_zstd.parquet"

    with ParquetReader(iris_parquet_path) as reader:
        # Check Parquet file metadata
        assert reader.parquet_file is not None
        assert reader.parquet_file.schema_arrow.names == [
            "sepal.length",
            "sepal.width",
            "petal.length",
            "petal.width",
            "species",
        ]
        assert reader.parquet_file.schema_arrow.types == [
            "float64",
            "float64",
            "float64",
            "float64",
            "string",
        ]
        assert reader.parquet_file.metadata.num_rows == 150
        assert reader.parquet_file.metadata.num_columns == 5
        assert reader.parquet_file.metadata.num_row_groups == 1

        # Read all records
        records = list(reader)

    assert len(records) == 150

    descriptor = records[0]._desc
    assert descriptor.name == "parquet/record"

    # Also tests if the renaming of fields from dot notation to underscore notation works correctly.
    assert descriptor.get_field_tuples() == (
        ("float", "sepal_length"),
        ("float", "sepal_width"),
        ("float", "petal_length"),
        ("float", "petal_width"),
        ("string", "species"),
    )
