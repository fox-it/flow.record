from hashlib import md5, sha1, sha256
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")

import pyarrow as pa
import pyarrow.parquet as pq

from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.adapter.parquet import ParquetReader, ParquetWriter
from flow.record.fieldtypes import posix_path, windows_path
from flow.record.tools import rdump
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

    digest_value = (
        md5(b"test").hexdigest(),
        sha1(b"test").hexdigest(),
        sha256(b"test").hexdigest(),
    )

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

    with (
        pytest.raises(Exception, match="Parquet file size is 0 bytes"),
        ParquetReader(parq_path) as reader,
    ):
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


@pytest.mark.parametrize(
    "exclude",
    [
        ["sepal.width", "petal.width"],
        ["sepal_width", "petal_width"],
    ],
)
def test_parquet_skip_columns(exclude: list[str]) -> None:
    """Test reading a Parquet file while skipping specified columns."""
    iris_parquet_path = Path(__file__).parent.parent / "_data" / "iris_zstd.parquet"

    with ParquetReader(iris_parquet_path, exclude=exclude) as reader:
        read_records = list(reader)

    # verify that the read records match the original records without the skipped column
    assert len(read_records) == 150
    for record in read_records:
        assert record.sepal_width is None
        assert record.petal_width is None
        assert record.petal_length is not None
        assert record.sepal_length is not None
        assert record.species is not None


@pytest.mark.parametrize(
    "fields",
    [
        ["sepal.length", "species"],
        ["sepal_length", "species"],
    ],
)
def test_parquet_only_columns(fields: list[str]) -> None:
    """Test reading a Parquet file while including only specified columns."""
    iris_parquet_path = Path(__file__).parent.parent / "_data" / "iris_zstd.parquet"

    with ParquetReader(iris_parquet_path, fields=fields) as reader:
        read_records = list(reader)

    # verify that the read records match the original records with only the included columns
    assert len(read_records) == 150
    for record in read_records:
        # these are the columns that should be auto skipped
        assert record.sepal_width is None
        assert record.petal_length is None
        assert record.petal_width is None
        # these are the only columns we included
        assert record.species is not None
        assert record.sepal_length is not None


def test_parquet_rdump(capsysbinary: pytest.CaptureFixture) -> None:
    """Test if rdump can read a Parquet file."""
    parquet_path = Path(__file__).parent.parent / "_data" / "iris_zstd.parquet"

    rdump.main([str(parquet_path), "-l"])
    out, err = capsysbinary.readouterr()

    assert (
        out.strip()
        == b"""
# <RecordDescriptor parquet/record, hash=b00e9d9b>
RecordDescriptor("parquet/record", [
    ("float", "sepal_length"),
    ("float", "sepal_width"),
    ("float", "petal_length"),
    ("float", "petal_width"),
    ("string", "species"),
    ("string", "_source"),
    ("string", "_classification"),
    ("datetime", "_generated"),
    ("varint", "_version"),
])

Processed 150 records (matched=150, unmatched=0)
""".strip()
    )

    assert err == b""


@pytest.mark.parametrize(
    "flag",
    [
        "--exclude-read",
        "-Xr",
    ],
)
def test_parquet_rdump_exclude_fields(flag: str, capsysbinary: pytest.CaptureFixture) -> None:
    """Test rdump functionality with ParquetReader while excluding certain fields."""
    parquet_path = Path(__file__).parent.parent / "_data" / "iris_zstd.parquet"
    rdump.main([str(parquet_path), "--exclude-read", "sepal.width", "--count=1"])
    out, err = capsysbinary.readouterr()
    assert (
        out.strip()
        == b"<parquet/record sepal_length=5.1 sepal_width=None petal_length=1.4 petal_width=0.2 species='Iris-setosa'>"
    )
    assert not err


@pytest.mark.parametrize(
    "flag",
    [
        "--fields-read",
        "-Fr",
    ],
)
def test_parquet_rdump_only_fields(flag: str, capsysbinary: pytest.CaptureFixture) -> None:
    """Test rdump functionality with ParquetReader while including only certain fields."""
    parquet_path = Path(__file__).parent.parent / "_data" / "iris_zstd.parquet"
    rdump.main([str(parquet_path), flag, "sepal.width", "--count=1"])
    out, err = capsysbinary.readouterr()
    assert (
        out.strip()
        == b"<parquet/record sepal_length=None sepal_width=3.5 petal_length=None petal_width=None species=None>"
    )
    assert not err


def test_parquet_mixed_path_serialization(tmp_path: Path) -> None:
    """Test that mixed path field types are correctly serialized and deserialized in Parquet."""
    TestRecord = RecordDescriptor("parquet/path", [("path", "file_path")])

    records = [
        TestRecord(file_path=posix_path("/home/user/test.txt")),
        TestRecord(file_path=windows_path("C:\\Users\\User\\test.txt")),
    ]

    with ParquetWriter(tmp_path / "paths.parquet") as writer:
        for record in records:
            writer.write(record)

    with ParquetReader(tmp_path / "paths.parquet") as reader:
        read_records = list(reader)

    assert len(read_records) == len(records)
    assert read_records == records
    assert isinstance(read_records[0].file_path, posix_path)
    assert isinstance(read_records[1].file_path, windows_path)


@pytest.mark.parametrize("batch_size", [10, 100, 1, 15, 1000])
def test_parquet_batchsize(tmp_path: Path, batch_size: int) -> None:
    """Test batch_size flushing in ParquetWriter."""
    out_path = tmp_path / f"{batch_size=}.parquet"

    # test via ParquetWriter and keyword argument
    records = list(generate_plain_records(batch_size * 2))
    with ParquetWriter(out_path, batch_size=batch_size) as writer:
        for record in records:
            writer.write(record)

    with ParquetReader(out_path) as reader:
        assert reader.parquet_file.metadata.num_rows == batch_size * 2
        assert reader.parquet_file.metadata.num_row_groups == 2
        read_records = list(reader)
    assert len(read_records) == batch_size * 2
    assert set(read_records) == set(records)

    # test via RecordWriter and parquet:// uri + parameters
    records = list(generate_plain_records(batch_size * 3))
    with RecordWriter(f"parquet://{out_path}?batch_size={batch_size}") as writer:
        for record in records:
            writer.write(record)

    with ParquetReader(out_path) as reader:
        assert reader.parquet_file.metadata.num_rows == batch_size * 3
        assert reader.parquet_file.metadata.num_row_groups == 3
        read_records = list(reader)
    assert len(read_records) == batch_size * 3
    assert set(read_records) == set(records)


def test_parquet_with_multiple_descriptors(tmp_path: Path) -> None:
    """Test writing and reading records with multiple descriptors using Parquet adapter."""

    MovieRecord = RecordDescriptor(
        "movie/record",
        [
            ("string", "title"),
            ("uint16", "year"),
        ],
    )
    ActorRecord = RecordDescriptor(
        "actor/record",
        [
            ("string", "name"),
            ("uint16", "birth_year"),
        ],
    )

    # create a list of mixed record descriptors
    records = []
    records.append(MovieRecord("Inception", 2010))
    records.append(ActorRecord("Leonardo DiCaprio", 1974))
    records.append(MovieRecord("The Matrix", 1999))
    records.append(ActorRecord("Keanu Reeves", 1964))
    records.append(MovieRecord("Interstellar", 2014))
    records.append(ActorRecord("Matthew McConaughey", 1969))

    # write the mixed records
    with ParquetWriter(tmp_path / "movies_and_actors.parquet") as writer:
        for record in records:
            writer.write(record)

    # check that we have written 2 parquet files
    fnames = {p.name for p in tmp_path.glob("*.parquet")}
    assert fnames == {"movies_and_actors.parquet", "movies_and_actors_actor_record_c5a59a6e.parquet"}

    # read them back in, and check if it matches the source
    read_records = []
    for fname in fnames:
        with ParquetReader(tmp_path / fname) as reader:
            read_records.extend(list(reader))

    assert set(read_records) == set(records)


@pytest.mark.parametrize("name", ["_", "+", "999", "%"])
def test_parquet_invalid_column_names(tmp_path: Path, name: str, caplog: pytest.LogCaptureFixture) -> None:
    # create PyArrow Table
    table = pa.table(
        {
            "id": [1, 2, 3],
            name: ["test", "test", "test"],
        }
    )

    # write to Parquet file
    output_file = tmp_path / "sample_data.parquet"
    pq.write_table(table, output_file)

    # read Parquet file, should trigger warning
    with ParquetReader(tmp_path / "sample_data.parquet") as reader:
        records = list(reader)
    assert len(records) == 3

    # check warnings
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert warnings[0].message == f"Dropping invalid field name in Arrow schema: '{name}' (original: '{name}')"
