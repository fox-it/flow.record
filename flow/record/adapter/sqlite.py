from __future__ import annotations

import logging
import sqlite3
from datetime import datetime
from typing import Iterator

from flow.record import Record, RecordDescriptor
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import RESERVED_FIELDS

logger = logging.getLogger(__name__)

__usage__ = """
SQLite adapter
---
Write usage: rdump -w sqlite://[PATH]
Read usage: rdump sqlite://[PATH]
[PATH]: path to sqlite database file
"""

# flow.record field mappings to SQLite types
FIELD_MAP = {
    "int": "INTEGER",
    "uint32": "INTEGER",
    "varint": "INTEGER",
    "float": "REAL",
    "boolean": "INTEGER",
    "bytes": "BLOB",
    "filesize": "INTEGER",
    "datetime": "TIMESTAMP",
}


# SQLite types to flow.record field mappings
SQLITE_FIELD_MAP = {
    "VARCHAR": "string",
    "INTEGER": "varint",
    "BLOB": "bytes",
    "REAL": "float",
    "DOUBLE": "float",
    "BOOLEAN": "boolean",
    "DATETIME": "datetime",
    "TIMESTAMP": "datetime",
}


def sanitized_name(name: str) -> str:
    """Returns a sanitized version of name.

    Some (field) names are not allowed in flow.record, while they can be allowed in SQLite.
    This sanitizes the name so it can still be used in flow.record.

        >>> sanitized_name("my-variable-name-with-dashes")
        'my_variable_name_with_dashes'
        >>> sanitized_name("_my_name_starting_with_underscore")
        'n__my_name_starting_with_underscore'
        >>> sanitized_name("1337")
        'n_1337'
    """

    if name not in RESERVED_FIELDS:
        name = name.replace("-", "_")
        if name.startswith("_") or name[0].isdecimal():
            name = "n_" + name
    return name


def create_descriptor_table(con: sqlite3.Connection, descriptor: RecordDescriptor) -> None:
    """Create table for a RecordDescriptor if it doesn't exists yet."""
    table_name = descriptor.name

    # Create column definitions (uses TEXT for unsupported types)
    column_defs = []
    for column_name, fieldset in descriptor.get_all_fields().items():
        column_type = FIELD_MAP.get(fieldset.typename, "TEXT")
        column_defs.append(f'   "{column_name}" {column_type}')
    sql_columns = ",\n".join(column_defs)

    # Create the descriptor table
    sql = f"""CREATE TABLE IF NOT EXISTS "{table_name}" (\n{sql_columns}\n)"""
    logger.debug(sql)
    con.execute(sql)


def update_descriptor_columns(con: sqlite3.Connection, descriptor: RecordDescriptor) -> None:
    """Update columns for descriptor table if new fields are added."""
    table_name = descriptor.name

    # Get existing columns
    cursor = con.execute(f'PRAGMA table_info("{table_name}")')
    column_names = set(row[1] for row in cursor.fetchall())

    # Add missing columns
    column_defs = []
    for column_name, fieldset in descriptor.get_all_fields().items():
        if column_name in column_names:
            continue
        column_type = FIELD_MAP.get(fieldset.typename, "TEXT")
        column_defs.append(f"  ALTER TABLE [{table_name}] ADD COLUMN [{column_name}] {column_type}")

    # No missing columns
    if not column_defs:
        return None

    # Add the new columns
    sql = ";\n".join(column_defs)
    con.executescript(sql)


def db_insert_record(con: sqlite3.Connection, record: Record) -> None:
    """Insert a record into the database."""
    table_name = record._desc.name
    rdict = record._asdict()

    # Construct placeholder SQL query
    column_names = ", ".join(f'"{name}"' for name in rdict.keys())
    value_placeholder = ", ".join(["?"] * len(rdict))
    sql = f"""INSERT INTO "{table_name}" ({column_names}) VALUES ({value_placeholder})"""

    # Convert values to str() for types we don't support
    values = []
    for value in rdict.values():
        if isinstance(value, datetime):
            value = value.isoformat()
        elif not (isinstance(value, (bytes, int, bool, float)) or value is None):
            value = str(value)
        values.append(value)

    # Insert record into database
    logger.debug(sql)
    logger.debug(values)
    con.execute(sql, values)


class SqliteReader(AbstractReader):
    def __init__(self, path, **kwargs):
        self.descriptors_seen = set()
        self.con = sqlite3.connect(path)
        self.count = 0
        self.batch_size = 1000
        self.rewrite = {}

    def table_names(self) -> list[str]:
        """Return a list of table names in the database."""
        records = self.con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return [record[0] for record in records]

    def read_table(self, table_name: str) -> Iterator[Record]:
        """Read a table from the database and yield records."""

        # flow.record is quite strict with what is allowed in fieldnames or decriptor name.
        # While SQLite is less strict, we need to sanitize the names to make them compatible.
        table_name_org = table_name
        table_name = sanitized_name(table_name)

        schema = self.con.execute(
            "SELECT c.type, c.name FROM pragma_table_info(?) c",
            [table_name_org],
        ).fetchall()

        fields = []
        fnames = []
        fname_to_type = {}
        for idx, row in enumerate(schema):
            ftype, fname = row
            fname = sanitized_name(fname)
            ftype = SQLITE_FIELD_MAP.get(ftype, "string")
            fname_to_type[fname] = ftype
            if fname not in RESERVED_FIELDS:
                fields.append((ftype, fname))
            fnames.append(fname)

        descriptor_cls = RecordDescriptor(table_name, fields)
        cursor = self.con.execute(f'SELECT * FROM "{table_name_org}"')
        while True:
            rows = cursor.fetchmany(self.batch_size)
            if not rows:
                break
            for row in rows:
                row = list(row)
                # A SQLite database could contain values not matching it's type (non STRICT mode)
                # So try to clean them up where we can.
                for idx, value in enumerate(row):
                    fname = fnames[idx]
                    ftype = fname_to_type[fname]
                    if ftype == "varint" and value == "":
                        row[idx] = None
                    elif ftype == "bytes":
                        if value == 0:
                            row[idx] = None
                        elif isinstance(value, str):
                            row[idx] = value.encode("utf-8")
                yield descriptor_cls.init_from_dict(dict(zip(fnames, row)))

    def __iter__(self):
        """Iterate over all tables in the database and yield records."""
        for table_name in self.table_names():
            logging.debug("Reading table: %s", table_name)
            yield from self.read_table(table_name)


class SqliteWriter(AbstractWriter):
    def __init__(self, path, **kwargs):
        self.descriptors_seen = set()
        self.con = None
        self.con = sqlite3.connect(path)
        self.count = 0
        self.batch_size = 1000

    def write(self, record: Record) -> None:
        """Write a record to the database"""
        desc = record._desc
        if desc not in self.descriptors_seen:
            self.descriptors_seen.add(desc)
            create_descriptor_table(self.con, desc)
            update_descriptor_columns(self.con, desc)

        db_insert_record(self.con, record)
        self.count += 1

        # Commit every batch_size records
        if self.count % self.batch_size == 0:
            self.con.commit()

    def flush(self):
        if self.con:
            self.con.commit()

    def close(self):
        if self.con:
            self.flush()
            self.con.close()
        self.con = None
