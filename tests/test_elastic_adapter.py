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
    ],
)


@pytest.mark.parametrize(
    "record",
    [
        MyRecord("first", "record"),
        MyRecord("second", "record"),
    ],
)
def test_elastic_writer_metadata(record: Record) -> None:
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
                    "field_one": record.field_one,
                    "field_two": record.field_two,
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
