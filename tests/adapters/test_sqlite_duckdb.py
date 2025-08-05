from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, NamedTuple

try:
    import duckdb
except ModuleNotFoundError:
    duckdb = None

import pytest

from flow.record import Record, RecordDescriptor, RecordReader, RecordWriter
from flow.record.adapter.sqlite import prepare_insert_sql
from flow.record.base import normalize_fieldname
from flow.record.exceptions import RecordDescriptorError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


class Database(NamedTuple):
    scheme: str
    connector: Any


# We test for sqlite3 and duckdb (if available)
if duckdb is None:
    databases = [
        Database("sqlite", sqlite3),
    ]
else:
    databases = [
        Database("sqlite", sqlite3),
        Database("duckdb", duckdb),
    ]

# pytest fixture that will run the test for each database in the databases list
sqlite_duckdb_parametrize = pytest.mark.parametrize("db", databases, ids=[db.scheme for db in databases])


def generate_records(amount: int) -> Iterator[Record]:
    """Generates some test records"""
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


@pytest.mark.parametrize(
    "table_name",
    [
        "my-movies",
        "movies",
        "123213",
        "_my_movies",
    ],
)
@sqlite_duckdb_parametrize
def test_table_name_sanitization(tmp_path: Path, table_name: str, db: Database) -> None:
    """Ensure that we can read table names that are technically invalid in flow.record."""
    db_path = tmp_path / "records.db"
    con = db.connector.connect(str(db_path))
    con.execute(f"CREATE TABLE '{table_name}' (title TEXT, year INTEGER, score DOUBLE)")
    data = [
        ("Monty Python Live at the Hollywood Bowl", 1982, 7.9),
        ("Monty Python's The Meaning of Life", 1983, 7.5),
        ("Monty Python's Life of Brian", 1979, 8.0),
    ]
    con.executemany(f"INSERT INTO '{table_name}' VALUES(?, ?, ?)", data)
    con.commit()
    con.close()

    data_records = []
    with RecordReader(f"{db.scheme}://{db_path}") as reader:
        data_records = [(record.title, record.year, record.score) for record in reader]
    assert data == data_records


@pytest.mark.parametrize(
    "field_name",
    [
        "normal_field_name",
        "_starting_with_underscore",
        "my-field-name",
        "1337_starting_with_number",
    ],
)
@sqlite_duckdb_parametrize
def test_field_name_sanitization(tmp_path: Path, field_name: str, db: Database) -> None:
    """Ensure that we can read field names that are technically invalid in flow.record."""
    db_path = tmp_path / "records.db"
    con = db.connector.connect(str(db_path))
    con.execute(f'CREATE TABLE "my_table" ("{field_name}" TEXT)')
    data = [
        ("hello",),
        ("world",),
        ("good",),
        ("bye",),
    ]
    con.executemany("INSERT INTO 'my_table' VALUES(?)", data)
    con.commit()
    con.close()

    data_records = []
    sanitized_field_name = normalize_fieldname(field_name)

    with RecordReader(f"{db.scheme}://{db_path}") as reader:
        data_records = [(getattr(record, sanitized_field_name),) for record in reader]
    assert data == data_records


@pytest.mark.parametrize(
    "count",
    [
        1337,
        1999,
        1000,
        2000,
    ],
)
@sqlite_duckdb_parametrize
def test_write_to_sqlite(tmp_path: Path, count: int, db: Database) -> None:
    """Tests writing records to a SQLite database."""
    db_path = tmp_path / "records.db"
    with RecordWriter(f"{db.scheme}://{db_path}") as writer:
        for record in generate_records(count):
            writer.write(record)

    record_count = 0
    with db.connector.connect(str(db_path)) as con:
        cursor = con.execute("SELECT COUNT(*) FROM 'test/record'")
        record_count = cursor.fetchone()[0]

        cursor = con.execute("SELECT * FROM 'test/record'")
        for index, row in enumerate(cursor.fetchall()):
            assert row[0] == f"record{index}"
            assert row[1] == "bar"
            assert row[2] == "baz"

        cursor = con.execute("SELECT * FROM 'test/record' WHERE name = 'record5'")
        row = cursor.fetchone()
        assert row[0] == "record5"
    assert record_count == count


@sqlite_duckdb_parametrize
def test_read_from_sqlite(tmp_path: Path, db: Database) -> None:
    """Tests basic reading from a SQLite database."""
    # Generate a SQLite database
    db_path = tmp_path / "records.db"
    with db.connector.connect(str(db_path)) as con:
        con.execute(
            """
            CREATE TABLE 'test/record' (
                name TEXT,
                data BLOB,
                datetime TIMESTAMPTZ,
                score DOUBLE
            )
            """
        )
        for i in range(1, 30):
            con.execute(
                """
                INSERT INTO 'test/record' VALUES (?, ?, ?, ?)
                """,
                (f"record{i}", f"foobar{i}".encode(), datetime(2023, 10, i, 13, 37, tzinfo=timezone.utc), 3.14 + i),
            )

    # Read the SQLite database using flow.record
    with RecordReader(f"{db.scheme}://{db_path}") as reader:
        for i, record in enumerate(reader, start=1):
            assert isinstance(record.name, str)
            assert isinstance(record.datetime, datetime)
            assert isinstance(record.data, bytes)
            assert isinstance(record.score, float)

            assert record.name == f"record{i}"
            assert record.data == f"foobar{i}".encode()
            assert record.datetime == datetime(2023, 10, i, 13, 37, tzinfo=timezone.utc)
            assert str(record.datetime) == f"2023-10-{i:02d} 13:37:00+00:00"
            assert record.score == 3.14 + i


@sqlite_duckdb_parametrize
def test_write_dynamic_descriptor(tmp_path: Path, db: Database) -> None:
    """Test the ability to write records with different descriptors to the same table."""
    db_path = tmp_path / "records.db"
    TestRecord = RecordDescriptor(
        "test/dynamic",
        [
            ("string", "name"),
            ("string", "foo"),
            ("string", "bar"),
        ],
    )
    TestRecord_extra = RecordDescriptor(
        "test/dynamic",
        [
            ("string", "name"),
            ("string", "foo"),
            ("string", "bar"),
            ("string", "extra"),
            ("string", "extra2"),
        ],
    )

    # We should be able to write records with different descriptors to the same table
    with RecordWriter(f"{db.scheme}://{db_path}") as writer:
        record1 = TestRecord(name="record1", foo="bar", bar="baz")
        writer.write(record1)
        record2 = TestRecord_extra(name="record2", foo="bar", bar="baz", extra="extra", extra2="extra2")
        writer.write(record2)

    # The read table should be a combination of both descriptors
    record_count = 0
    with RecordReader(f"{db.scheme}://{db_path}") as reader:
        for record_count, record in enumerate(reader, start=1):
            assert record._desc.get_field_tuples() == (
                ("string", "name"),
                ("string", "foo"),
                ("string", "bar"),
                ("string", "extra"),
                ("string", "extra2"),
            )
            if record_count == 1:
                assert record.extra is None
                assert record.extra2 is None
            else:
                assert record.extra == "extra"
                assert record.extra2 == "extra2"

    assert record_count == 2


@sqlite_duckdb_parametrize
def test_write_zero_records(tmp_path: Path, db: Database) -> None:
    """Test writing zero records."""
    db_path = tmp_path / "records.db"
    with RecordWriter(f"{db.scheme}://{db_path}") as writer:
        assert writer

    # test if it's a valid database
    with db.connector.connect(str(db_path)) as con:
        assert con.execute("SELECT * FROM sqlite_master").fetchall() == []


@pytest.mark.parametrize(
    ("sqlite_coltype", "sqlite_value", "expected_value"),
    [
        ("INTEGER", 1, 1),
        ("INTEGER", "3", 3),
        ("INTEGER", "", None),
        ("BLOB", None, None),
        ("BLOB", 0, None),
        ("BLOB", b"blob", b"blob"),
        ("BLOB", "text", b"text"),
        ("BLOB", "", b""),
        ("BLOB", b"", b""),
    ],
)
def test_non_strict_sqlite_fields(tmp_path: Path, sqlite_coltype: str, sqlite_value: Any, expected_value: Any) -> None:
    """SQLite by default is non strict, meaning that the value could be of different type than the column type."""
    db = tmp_path / "records.db"
    with sqlite3.connect(db) as con:
        con.execute(f"CREATE TABLE 'strict-test' (field {sqlite_coltype})")
        con.execute("INSERT INTO 'strict-test' VALUES(?)", (sqlite_value,))

    with RecordReader(f"sqlite://{db}") as reader:
        record = next(iter(reader))
        assert record.field == expected_value


@pytest.mark.parametrize(
    "invalid_table_name",
    [
        "'single_quote",
        '"double_quote',
        "`backtick",
    ],
)
def test_invalid_table_names_quoting(tmp_path: Path, invalid_table_name: str) -> None:
    """Test if we get proper exception when table name is invalid for flow.record."""

    # Creating the tables with these invalid_table_names in SQLite is no problem
    db = tmp_path / "records.db"
    with sqlite3.connect(db) as con:
        con.execute(f"CREATE TABLE [{invalid_table_name}] (field TEXT, field2 TEXT)")
        con.execute(f"INSERT INTO [{invalid_table_name}] VALUES(?, ?)", ("hello", "world"))
        con.execute(f"INSERT INTO [{invalid_table_name}] VALUES(?, ?)", ("goodbye", "planet"))

    # However, these invalid_table_names should raise an exception when reading
    with (
        pytest.raises(RecordDescriptorError, match="Invalid record type name"),
        RecordReader(f"sqlite://{db}") as reader,
    ):
        _ = next(iter(reader))


@pytest.mark.parametrize(
    "invalid_field_name",
    [
        "'single_quote",
        '"double_quote',
        "`backtick",
    ],
)
def test_invalid_field_names_quoting(tmp_path: Path, invalid_field_name: str) -> None:
    """Test if we get proper exception when SQLite field name is invalid for flow.record."""

    # Creating the table with invalid field name in SQLite is no problem
    db = tmp_path / "records.db"
    with sqlite3.connect(db) as con:
        con.execute(f"CREATE TABLE [test] (field TEXT, [{invalid_field_name}] TEXT)")
        con.execute("INSERT INTO [test] VALUES(?, ?)", ("hello", "world"))
        con.execute("INSERT INTO [test] VALUES(?, ?)", ("goodbye", "planet"))

    # However, these field names are invalid in flow.record and should raise an exception
    with (
        pytest.raises(RecordDescriptorError, match="Field .* is an invalid or reserved field name."),
        RecordReader(f"sqlite://{db}") as reader,
    ):
        _ = next(iter(reader))


def test_prepare_insert_sql() -> None:
    table_name = "my_table"
    field_names = ("name", "age", "email")
    expected_sql = 'INSERT INTO "my_table" ("name", "age", "email") VALUES (?, ?, ?)'
    assert prepare_insert_sql(table_name, field_names) == expected_sql


@pytest.mark.parametrize(
    ("batch_size", "expected_first", "expected_second"),
    [
        (1, 1, 2),
        (10, 0, 10),
        (100, 0, 100),
        (1000, 0, 1000),
    ],
)
@sqlite_duckdb_parametrize
def test_batch_size(
    tmp_path: Path,
    batch_size: int,
    expected_first: int,
    expected_second: int,
    db: Database,
) -> None:
    """Test that batch_size is respected when writing records."""
    records = generate_records(batch_size + 100)
    db_path = tmp_path / "records.db"
    with RecordWriter(f"{db.scheme}://{db_path}?batch_size={batch_size}") as writer:
        # write a single record, should not be flushed yet if batch_size > 1
        writer.write(next(records))

        # test count of records in table (no flush yet if batch_size > 1)
        with db.connector.connect(str(db_path)) as con:
            x = con.execute('SELECT COUNT(*) FROM "test/record"')
            assert x.fetchone()[0] is expected_first

        # write at least batch_size records, should be flushed due to batch_size
        for _i in range(batch_size):
            writer.write(next(records))

        # test count of records in table after flush
        with db.connector.connect(str(db_path)) as con:
            x = con.execute('SELECT COUNT(*) FROM "test/record"')
            assert x.fetchone()[0] == expected_second


@sqlite_duckdb_parametrize
def test_selector(tmp_path: Path, db: Database) -> None:
    """Test selector when reading records."""
    db_path = tmp_path / "records.db"
    with RecordWriter(f"{db.scheme}://{db_path}") as writer:
        for record in generate_records(10):
            writer.write(record)

    with RecordReader(f"{db.scheme}://{db_path}", selector="r.name == 'record5'") as reader:
        records = list(reader)
        assert len(records) == 1
        assert records[0].name == "record5"

    with RecordReader(f"{db.scheme}://{db_path}", selector="r.name == 'record12345'") as reader:
        records = list(reader)
        assert len(records) == 0
