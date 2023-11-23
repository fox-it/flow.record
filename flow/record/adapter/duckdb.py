from __future__ import annotations

import logging

import duckdb

from flow.record.adapter.sqlite import (
    Selector,
    SqliteReader,
    SqliteWriter,
    make_selector,
)

logger = logging.getLogger(__name__)

__usage__ = """
DuckDB adapter
---
Write usage: rdump -w duckdb://[PATH]?batch_size=[BATCH_SIZE]
Read usage: rdump duckdb://[PATH]?batch_size=[BATCH_SIZE]
[PATH]: path to DuckDB database file

Optional parameters:
    [BATCH_SIZE]: number of records to read or write in a single transaction (default: 1000)
"""


class DuckdbReader(SqliteReader):
    """DuckDB reader, subclasses from SQLite reader."""

    logger = logger

    def __init__(self, path: str, *, batch_size: str | int = 1000, selector: Selector | str | None = None, **kwargs):
        self.selector = make_selector(selector)
        self.descriptors_seen = set()
        self.con = duckdb.connect(path)
        self.count = 0
        self.batch_size = int(batch_size)


class DuckdbWriter(SqliteWriter):
    """DuckDB writer, subclasses from SQLite writer."""

    logger = logger

    def __init__(self, path: str, *, batch_size: str | int = 1000, **kwargs):
        self.descriptors_seen = set()
        self.con = None
        self.con = duckdb.connect(path)
        self.count = 0
        self.batch_size = int(batch_size)
        self.con.begin()

    def tx_cycle(self) -> None:
        self.con.commit()
        self.con.begin()
