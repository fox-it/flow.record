from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated

import pytest

from flow.record import RecordDescriptor
from flow.record.declarative import RecordBase

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


ClassicRecord = RecordDescriptor(
    "test/benchmark",
    [
        ("datetime", "ts"),
        ("string", "url"),
        ("uint32", "status"),
        ("string", "remote"),
    ],
)


class DeclarativeRecord(RecordBase, name="test/benchmark"):
    ts: datetime
    url: str
    status: Annotated[int, "uint32"]
    remote: str


@pytest.mark.benchmark
def test_benchmark_classic_init(benchmark: BenchmarkFixture) -> None:
    """Benchmark constructing a classic ``RecordDescriptor``-generated record."""
    ts = datetime.now(timezone.utc)
    benchmark(lambda: ClassicRecord(ts=ts, url="http://flow.record", status=200, remote="127.0.0.1"))


@pytest.mark.benchmark
def test_benchmark_declarative_init(benchmark: BenchmarkFixture) -> None:
    """Benchmark constructing a declarative ``RecordBase`` record with the same fields."""
    ts = datetime.now(timezone.utc)
    benchmark(lambda: DeclarativeRecord(ts=ts, url="http://flow.record", status=200, remote="127.0.0.1"))
