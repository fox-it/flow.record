# ruff: noqa: E501
from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING

import pytest
from elasticsearch.helpers import BulkIndexError

from flow.record import RecordDescriptor
from flow.record.adapter.elastic import ElasticWriter, create_elasticsearch_error_notes

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

        with pytest.raises(BulkIndexError) as exc_info:
            writer.__exit__()

        writer.exception = None
        exception = exc_info.value
        assert isinstance(exception, BulkIndexError)

        # version guard for __notes__ attribute, which was added in Python 3.11
        # TODO: Remove after we drop support for Python 3.10
        if sys.version_info >= (3, 11):
            assert exception.__notes__ == [
                """\
Error 1, 'document_parsing_exception' (status=400):
  index: example-index
  document_id: bWFkZSB5b3UgbG9vayDwn5GA
  reason: [1:225] failed to parse field [example] of type [long] in document with id 'bWFkZSB5b3UgbG9vayDwn5GA'. Preview of field's value: 'Foo'
  caused_by: illegal_argument_exception, reason: For input string: "Foo"
  descriptor_name: example/record
  data: {"example": "Foo"}
"""
            ]


def test_create_elastic_notes() -> None:
    exception = BulkIndexError(
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
                },
            },
            {
                "index": {
                    "_index": "my-index",
                    "_id": "4XuIRpwBbjwxMKSCr8TE",
                    "status": 400,
                    "error": {
                        "type": "document_parsing_exception",
                        "reason": "[1:150] failed to parse field [content] of type [date] in document with id '4XuIRpwBbjwxMKSCr8TE'. Preview of field's value: 'This is the content of a sampe pastebin record'",
                        "caused_by": {
                            "type": "illegal_argument_exception",
                            "reason": "failed to parse date field [This is the content of a sampe pastebin record] with format [strict_date_optional_time||epoch_millis]",
                            "caused_by": {
                                "type": "date_time_parse_exception",
                                "reason": "Failed to parse with all enclosed parsers",
                            },
                        },
                    },
                    "data": '{"key": "Q42eWSaF", "date": "2019-03-19T09:09:47+00:00", "expire_date": "1970-01-01T00:00:00+00:00", "title": "A sample pastebin record", "content": "This is the content of a sampe pastebin record", "user": "", "syntax": "text", "_record_metadata": {"descriptor": {"name": "text/paste", "hash": 831446724}, "source": "external/pastebin", "classification": "PUBLIC", "generated": "2019-03-19T09:11:04.706581+00:00", "version": 1}}',
                }
            },
        ],
    )
    errors = exception.errors
    assert len(errors) == 2

    # Test with max_notes=1, which should only include the first error and a summary note about the remaining errors
    notes = create_elasticsearch_error_notes(errors, max_notes=1)
    assert len(notes) == 2
    assert (
        notes[0]
        == """\
Error 1, 'document_parsing_exception' (status=400):
  index: example-index
  document_id: bWFkZSB5b3UgbG9vayDwn5GA
  reason: [1:225] failed to parse field [example] of type [long] in document with id 'bWFkZSB5b3UgbG9vayDwn5GA'. Preview of field's value: 'Foo'
  caused_by: illegal_argument_exception, reason: For input string: "Foo"
  descriptor_name: example/record
  data: {"example": "Foo"}
"""
    )
    assert notes[-1] == "... and 1 more error(s) not shown."

    # Test with max_notes=2, which should show both errors without the summary note
    notes = create_elasticsearch_error_notes(errors, max_notes=2)
    assert len(notes) == 2
    assert (
        notes[0]
        == """\
Error 1, 'document_parsing_exception' (status=400):
  index: example-index
  document_id: bWFkZSB5b3UgbG9vayDwn5GA
  reason: [1:225] failed to parse field [example] of type [long] in document with id 'bWFkZSB5b3UgbG9vayDwn5GA'. Preview of field's value: 'Foo'
  caused_by: illegal_argument_exception, reason: For input string: "Foo"
  descriptor_name: example/record
  data: {"example": "Foo"}
"""
    )
    assert (
        notes[1]
        == """\
Error 2, 'document_parsing_exception' (status=400):
  index: my-index
  document_id: 4XuIRpwBbjwxMKSCr8TE
  reason: [1:150] failed to parse field [content] of type [date] in document with id '4XuIRpwBbjwxMKSCr8TE'. Preview of field's value: 'This is the content of a sampe pastebin record'
  caused_by: illegal_argument_exception, reason: failed to parse date field [This is the content of a sampe pastebin record] with format [strict_date_optional_time||epoch_millis]
  descriptor_name: text/paste
  data: {"key": "Q42eWSaF", "date": "2019-03-19T09:09:47+00:00", "expire_date": "1970-01-01T00:00:00+00:00", "title": "A sample pastebin record", "content": "This is the content of a sampe pastebin record", "user": "", "syntax": "text"}
"""
    )
