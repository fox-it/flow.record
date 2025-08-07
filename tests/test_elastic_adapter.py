from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from elasticsearch.helpers import BulkIndexError

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


def test_elastic_writer_metadata_exception() -> None:
    with ElasticWriter(uri="elasticsearch:9200") as writer:
        writer.excepthook(
            BulkIndexError(
                "1 document(s) failed to index.",
                errors=[
                    {
                        "index": {
                            "_index": "example-index",
                            "_id": "bWFkZSB5b3UgbG9vayDwn5GA",
                            "status": 400,
                            "error": {
                                "type": "document_parsing_exception",
                                "reason": "[1:225] failed to parse field [example] of type [long] in document with id "
                                "'bWFkZSB5b3UgbG9vayDwn5GA'. Preview of field's value: 'Foo'",
                                "caused_by": {
                                    "type": "illegal_argument_exception",
                                    "reason": 'For input string: "Foo"',
                                },
                            },
                            "data": '{"example":"Foo","_record_metadata":{"descriptor":{"name":"example/record",'
                            '"hash":1234567890},"source":"/path/to/source","classification":null,'
                            '"generated":"2025-12-31T12:34:56.789012+00:00","version":1}}',
                        }
                    }
                ],
            )
        )

        assert writer.exception.args == (
            (
                "1 document(s) failed to index. (example/record: 400 "
                "document_parsing_exception [1:225] failed to parse field "
                "[example] of type [long] in document with id 'bWFkZSB5b3UgbG9vayDwn5GA'. "
                "Preview of field's value: 'Foo')"
            ),
        )

        with pytest.raises(BulkIndexError):
            writer.__exit__()

        writer.exception = None
