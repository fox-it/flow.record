import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from flow.record import Record, RecordDescriptor, RecordReader, RecordWriter
from flow.record.adapter.sqlite import sanitized_name


def generate_records(amount: int) -> Record:
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
def test_table_name_sanitization(tmp_path: Path, table_name: str) -> None:
    """Ensure that we can read table names that are technically invalid in flow.record."""
    db = tmp_path / "records.db"
    con = sqlite3.connect(db)
    con.execute(f"CREATE TABLE '{table_name}' (title TEXT, year INTEGER, score REAL)")
    data = [
        ("Monty Python Live at the Hollywood Bowl", 1982, 7.9),
        ("Monty Python's The Meaning of Life", 1983, 7.5),
        ("Monty Python's Life of Brian", 1979, 8.0),
    ]
    con.executemany(f"INSERT INTO '{table_name}' VALUES(?, ?, ?)", data)
    con.commit()
    con.close()

    data_records = []
    with RecordReader(f"sqlite://{db}") as reader:
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
def test_field_name_sanitization(tmp_path: Path, field_name: str) -> None:
    """Ensure that we can read field names that are technically invalid in flow.record."""
    db = tmp_path / "records.db"
    con = sqlite3.connect(db)
    con.execute(f"CREATE TABLE 'my_table' ('{field_name}' TEXT)")
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
    sanitized_field_name = sanitized_name(field_name)

    with RecordReader(f"sqlite://{db}") as reader:
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
def test_write_to_sqlite(tmp_path: Path, count: int) -> None:
    """Tests writing records to a SQLite database."""
    db = tmp_path / "records.db"
    with RecordWriter(f"sqlite://{db}") as writer:
        for record in generate_records(count):
            writer.write(record)

    record_count = 0
    with sqlite3.connect(db) as con:
        cursor = con.execute("SELECT COUNT(*) FROM 'test/record'")
        record_count = cursor.fetchone()[0]

        cursor = con.execute("SELECT * FROM 'test/record'")
        for index, row in enumerate(cursor):
            assert row[0] == f"record{index}"
            assert row[1] == "bar"
            assert row[2] == "baz"

        cursor = con.execute("SELECT * FROM 'test/record' WHERE name = 'record5'")
        row = cursor.fetchone()
        assert row[0] == "record5"
    assert record_count == count


def test_read_from_sqlite(tmp_path: Path) -> None:
    """Tests basic reading from a SQLite database."""
    # Generate a SQLite database
    db = tmp_path / "records.db"
    with sqlite3.connect(db) as con:
        con.execute(
            """
            CREATE TABLE 'test/record' (
                name TEXT,
                data BLOB,
                datetime DATETIME,
                score REAL
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
    with RecordReader(f"sqlite://{db}") as reader:
        for i, record in enumerate(reader, start=1):
            assert isinstance(record.name, str)
            assert isinstance(record.datetime, datetime)
            assert isinstance(record.data, bytes)
            assert isinstance(record.score, float)

            assert record.name == f"record{i}"
            assert record.data == f"foobar{i}".encode()
            assert record.datetime == datetime(2023, 10, i, 13, 37, tzinfo=timezone.utc)
            assert record.score == 3.14 + i


def test_write_dynamic_descriptor(tmp_path: Path) -> None:
    """Test the ability to write records with different descriptors to the same table."""
    db = tmp_path / "records.db"
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
    with RecordWriter(f"sqlite://{db}") as writer:
        record1 = TestRecord(name="record1", foo="bar", bar="baz")
        writer.write(record1)
        record2 = TestRecord_extra(name="record2", foo="bar", bar="baz", extra="extra", extra2="extra2")
        writer.write(record2)

    # The read table should be a combination of both descriptors
    record_count = 0
    with RecordReader(f"sqlite://{db}") as reader:
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


def test_write_zero_records(tmp_path: Path):
    """Test writing zero records."""
    db = tmp_path / "records.db"
    with RecordWriter(f"sqlite://{db}") as writer:
        assert writer

    # test if it's a valid database
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT * FROM sqlite_master").fetchall() == []


@pytest.mark.parametrize(
    "sqlite_coltype, sqlite_value, expected_value",
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
