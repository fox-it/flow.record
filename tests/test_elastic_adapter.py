from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from flow.record import RecordDescriptor
from flow.record.adapter.elastic import ElasticWriter

if TYPE_CHECKING:
    from flow.record.base import Record

MyRecord = RecordDescriptor(
    "my/record",
    [
        ("string", "field_one"),
        ("string", "field_two"),
        ("string", "field_three"),
    ],
)

AnotherRecord = RecordDescriptor(
    "my/record",
    [
        ("command", "field_one"),
        ("boolean", "field_two"),
        ("bytes", "field_three"),
    ],
)


@pytest.mark.parametrize(
    "record, expected_output",
    [
        (
            MyRecord("first", "record", "!"),
            {
                "field_one": "first",
                "field_two": "record",
                "field_three": "!",
            },
        ),
        (
            MyRecord("second", "record", "!"),
            {
                "field_one": "second",
                "field_two": "record",
                "field_three": "!",
            },
        ),
        (
            AnotherRecord("/bin/bash -c 'echo hello'", False, b"\x01\x02\x03\x04"),
            {
                "field_one": "/bin/bash -c 'echo hello'",
                "field_two": False,
                "field_three": "AQIDBA==",
            },
        ),
    ],
)
def test_elastic_writer_metadata(record: MyRecord | AnotherRecord, expected_output: dict) -> None:
    options = {
        "_meta_foo": "some value",
        "_meta_bar": "another value",
    }

    with ElasticWriter(uri="elasticsearch:9200", **options) as writer:
        assert writer.metadata_fields == {"foo": "some value", "bar": "another value"}

        assert writer.record_to_document(record, "some-index") == {
            "_index": "some-index",
            "_source": json.dumps(
                {
                    **expected_output,
                    "_record_metadata": {
                        "descriptor": {
                            "name": "my/record",
                            "hash": record._desc.descriptor_hash,
                        },
                        "source": None,
                        "classification": None,
                        "generated": record._generated.isoformat(),
                        "version": 1,
                        "foo": "some value",
                        "bar": "another value",
                    },
                }
            ),
        }
