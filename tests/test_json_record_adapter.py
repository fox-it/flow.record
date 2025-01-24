from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from flow.record import RecordReader, RecordWriter

from ._utils import generate_records

if TYPE_CHECKING:
    from pathlib import Path


def test_json_adapter(tmp_path: Path) -> None:
    json_file = tmp_path.joinpath("records.json")
    record_adapter_path = f"jsonfile://{json_file}"
    writer = RecordWriter(record_adapter_path)
    nr_records = 1337

    for record in generate_records(nr_records):
        writer.write(record)
    writer.flush()

    nr_received_records = 0
    reader = RecordReader(record_adapter_path)
    for _ in reader:
        nr_received_records += 1

    assert nr_records == nr_received_records


def test_json_adapter_contextmanager(tmp_path: Path) -> None:
    json_file = tmp_path.joinpath("records.json")
    record_adapter_path = f"jsonfile://{json_file}"
    with RecordWriter(record_adapter_path) as writer:
        nr_records = 1337
        for record in generate_records(nr_records):
            writer.write(record)

    nr_received_records = 0
    with RecordReader(record_adapter_path) as reader:
        for _ in reader:
            nr_received_records += 1

        assert nr_records == nr_received_records


def test_json_adapter_jsonlines(tmp_path: Path) -> None:
    json_file = tmp_path.joinpath("data.jsonl")

    items = [
        {"some_float": 1.5, "some_string": "hello world", "some_int": 1337, "some_bool": True},
        {"some_float": 2.7, "some_string": "goodbye world", "some_int": 12345, "some_bool": False},
    ]
    with json_file.open("w") as fout:
        for row in items:
            fout.write(json.dumps(row) + "\n")

    record_adapter_path = f"jsonfile://{json_file}"
    reader = RecordReader(record_adapter_path)
    for index, record in enumerate(reader):
        assert record.some_float == items[index]["some_float"]
        assert record.some_string == items[index]["some_string"]
        assert record.some_int == items[index]["some_int"]
        assert record.some_bool == items[index]["some_bool"]


@pytest.mark.parametrize(
    "record_adapter_path",
    [
        "jsonfile://{json_file}?descriptors=False",
        "jsonfile://{json_file}?descriptors=false",
        "jsonfile://{json_file}?descriptors=0",
    ],
)
def test_json_adapter_no_record_descriptors(tmp_path: Path, record_adapter_path: str) -> None:
    json_file = tmp_path.joinpath("records.jsonl")
    record_adapter_path = record_adapter_path.format(json_file=json_file)

    with RecordWriter(record_adapter_path) as writer:
        for record in generate_records(100):
            writer.write(record)
            writer.flush()

    with json_file.open() as fin:
        for line in fin:
            record = json.loads(line)
            assert "_recorddescriptor" not in record
            assert "_type" not in record


@pytest.mark.parametrize(
    "record_adapter_path",
    [
        "jsonfile://{json_file}?descriptors=True",
        "jsonfile://{json_file}?descriptors=true",
        "jsonfile://{json_file}?descriptors=1",
    ],
)
def test_json_adapter_with_record_descriptors(tmp_path: Path, record_adapter_path: str) -> None:
    json_file = tmp_path.joinpath("records.jsonl")
    record_adapter_path = record_adapter_path.format(json_file=json_file)

    with RecordWriter(record_adapter_path) as writer:
        for record in generate_records(100):
            writer.write(record)
            writer.flush()

    descriptor_seen = 0
    with json_file.open() as fin:
        for line in fin:
            record = json.loads(line)
            assert "_type" in record
            if record["_type"] == "recorddescriptor":
                descriptor_seen += 1
            elif record["_type"] == "record":
                assert "_recorddescriptor" in record
    assert descriptor_seen == 2
