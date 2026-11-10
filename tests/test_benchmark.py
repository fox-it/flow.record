from __future__ import annotations

import io
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from flow.record import (
    JsonRecordPacker,
    RecordDescriptor,
    RecordPacker,
    RecordStreamReader,
    RecordStreamWriter,
    RecordWriter,
)
from flow.record.base import _generate_record_class
from flow.record.selector import make_selector

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

FIELDS = [
    ("datetime", "ts"),
    ("string", "name"),
    ("varint", "size"),
    ("boolean", "hidden"),
    ("path", "path"),
    ("string[]", "tags"),
    ("net.ipaddress", "ip"),
]

VALUES = {
    "ts": datetime(2024, 3, 1, 12, 30, 15, 123456, tzinfo=timezone.utc),
    "name": "base.py",
    "size": 41213,
    "hidden": False,
    "path": "/usr/lib/python3/flow/record/base.py",
    "tags": ["python", "source"],
    "ip": "10.13.37.4",
}

TestRecord = RecordDescriptor("test/benchmark", FIELDS)


@pytest.mark.benchmark
def test_benchmark_create(benchmark: BenchmarkFixture) -> None:
    """Benchmark creating a record from keyword arguments."""
    benchmark(lambda: TestRecord(**VALUES))


@pytest.mark.benchmark
@pytest.mark.parametrize("packer", [RecordPacker, JsonRecordPacker], ids=["msgpack", "json"])
@pytest.mark.parametrize("direction", ["pack", "unpack"])
def test_benchmark_packer(
    packer: type[RecordPacker | JsonRecordPacker], direction: str, benchmark: BenchmarkFixture
) -> None:
    """Benchmark packing and unpacking a record."""
    packer = packer()
    packer.register(TestRecord)
    record = TestRecord(**VALUES)

    if direction == "pack":
        benchmark(lambda: packer.pack(record))
    else:
        data = packer.pack(record)
        benchmark(lambda: packer.unpack(data))


@pytest.mark.benchmark
@pytest.mark.parametrize("direction", ["write", "read"])
def test_benchmark_stream(direction: str, benchmark: BenchmarkFixture) -> None:
    """Benchmark writing and reading a record stream of 100 records."""
    records = [TestRecord(**VALUES) for _ in range(100)]

    def write() -> bytes:
        fp = io.BytesIO()
        writer = RecordStreamWriter(fp)
        for record in records:
            writer.write(record)
        writer.flush()
        return fp.getvalue()

    if direction == "write":
        benchmark(write)
    else:
        data = write()
        benchmark(lambda: list(RecordStreamReader(io.BytesIO(data))))


@pytest.mark.benchmark
@pytest.mark.parametrize("adapter", ["text", "jsonfile", "csvfile", "line"])
def test_benchmark_writer(adapter: str, benchmark: BenchmarkFixture) -> None:
    """Benchmark writing a record with the text based adapters."""
    record = TestRecord(**VALUES)

    with RecordWriter(f"{adapter}://{os.devnull}") as writer:
        benchmark(lambda: writer.write(record))


@pytest.mark.benchmark
@pytest.mark.parametrize("compiled", [True, False], ids=["compiled", "interpreted"])
def test_benchmark_selector(compiled: bool, benchmark: BenchmarkFixture) -> None:
    """Benchmark matching a record against a selector."""
    record = TestRecord(**VALUES)
    selector = make_selector("r.name == 'base.py' and r.size > 4096 and not r.hidden", compiled)

    benchmark(lambda: selector.match(record))


@pytest.mark.benchmark
def test_benchmark_record_class(benchmark: BenchmarkFixture) -> None:
    """Benchmark generating the record class of a new descriptor."""
    fields = tuple(FIELDS)

    # Bypass the cache of generated record classes
    benchmark(lambda: _generate_record_class.__wrapped__("test/benchmark", fields))
