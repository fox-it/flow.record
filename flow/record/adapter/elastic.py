from __future__ import annotations

import hashlib
import json
import logging
import queue
import sys
import threading
from contextlib import suppress
from typing import TYPE_CHECKING

import urllib3

try:
    import elasticsearch
    import elasticsearch.helpers

    HAS_ELASTIC = True

except ImportError:
    HAS_ELASTIC = False

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import Record, RecordDescriptor
from flow.record.context import get_app_context, match_record_with_context
from flow.record.fieldtypes import fieldtype_for_value
from flow.record.jsonpacker import JsonRecordPacker
from flow.record.utils import boolean_argument

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.selector import CompiledSelector, Selector

__usage__ = """
ElasticSearch adapter
---
Write usage: rdump -w elastic+[PROTOCOL]://[IP]:[PORT]?index=[INDEX]
Read usage: rdump elastic+[PROTOCOL]://[IP]:[PORT]?index=[INDEX]
[IP]:[PORT]: ip and port to elastic host
[PROTOCOL]: http or https. Defaults to https when "+[PROTOCOL]" is omitted

Optional arguments:
  [API_KEY]: base64 encoded api key to authenticate with (default: False)
  [QUEUE_SIZE]: maximum queue size for writing records; limits memory usage (default: 100000)
  [INDEX]: name of the index to use (default: records)
  [VERIFY_CERTS]: verify certs of Elasticsearch instance (default: True)
  [HASH_RECORD]: make record unique by hashing record [slow] (default: False)
  [REQUEST_TIMEOUT]: maximum duration in seconds for a request to Elastic (default: 30)
  [MAX_RETRIES]: maximum retries before a record is marked as failed (default: 3)
  [_META_*]: record metadata fields (default: None)
"""

log = logging.getLogger(__name__)


class ElasticWriter(AbstractWriter):
    def __init__(
        self,
        uri: str,
        index: str = "records",
        verify_certs: str | bool = True,
        http_compress: str | bool = True,
        hash_record: str | bool = False,
        api_key: str | None = None,
        queue_size: int = 100000,
        request_timeout: int = 30,
        max_retries: int = 3,
        **kwargs,
    ) -> None:
        """Initialize the ElasticWriter.

        Resources:
            - https://elasticsearch-py.readthedocs.io/en/v8.17.1/api/elasticsearch.html
        """

        if not HAS_ELASTIC:
            raise RuntimeError("Required dependency 'elasticsearch' missing")

        self.index = index
        self.uri = uri
        verify_certs = boolean_argument(verify_certs)
        http_compress = boolean_argument(http_compress)
        self.hash_record = boolean_argument(hash_record)
        queue_size = int(queue_size)
        request_timeout = int(request_timeout)
        self.max_retries = int(max_retries)

        if not uri.lower().startswith(("http://", "https://")):
            uri = "https://" + uri

        self.queue: queue.Queue[Record | StopIteration] = queue.Queue(maxsize=queue_size)
        self.event = threading.Event()
        self.exception: Exception | None = None
        threading.excepthook = self.excepthook

        self.es = elasticsearch.Elasticsearch(
            uri,
            verify_certs=verify_certs,
            ssl_show_warn=verify_certs,
            http_compress=http_compress,
            api_key=api_key,
            request_timeout=request_timeout,
            retry_on_timeout=True,
            max_retries=self.max_retries,
        )

        self.json_packer = JsonRecordPacker()

        self.thread = threading.Thread(target=self.streaming_bulk_thread)
        self.thread.start()

        self.metadata_fields = {}
        for arg_key, arg_val in kwargs.items():
            if arg_key.startswith("_meta_"):
                self.metadata_fields[arg_key[6:]] = arg_val

    def excepthook(self, exc: threading.ExceptHookArgs, *args, **kwargs) -> None:
        self.exception = getattr(exc, "exc_value", exc)

        # version guard for add_note(), which was added in Python 3.11
        # TODO: Remove version guard after dropping support for Python 3.10
        if sys.version_info >= (3, 11):
            for note in create_elasticsearch_error_notes(getattr(self.exception, "errors", []), max_notes=5):
                self.exception.add_note(note)

        self.event.set()

    def record_to_document(self, record: Record, index: str) -> dict:
        """Convert a record to a Elasticsearch compatible document dictionary"""
        rdict = record._asdict()

        # Store record metadata under `_record_metadata`.
        rdict_meta = {
            "descriptor": {
                "name": record._desc.name,
                "hash": record._desc.descriptor_hash,
            },
        }

        # Move all dunder fields to `_record_metadata` to avoid naming clash with ES.
        dunder_keys = [key for key in rdict if key.startswith("_")]
        for key in dunder_keys:
            rdict_meta[key.lstrip("_")] = rdict.pop(key)

        # Remove _generated field from metadata to ensure determinstic documents.
        if self.hash_record:
            rdict_meta.pop("generated", None)

        rdict["_record_metadata"] = rdict_meta.copy()
        rdict["_record_metadata"].update(self.metadata_fields)

        document = {
            "_index": index,
            "_source": self.json_packer.pack(rdict),
        }

        if self.hash_record:
            document["_id"] = hashlib.md5(document["_source"].encode(errors="surrogateescape")).hexdigest()

        return document

    def document_stream(self) -> Iterator[dict]:
        """Generator of record documents on the Queue"""
        while True:
            record = self.queue.get()
            if record is StopIteration:
                break
            if not record:
                continue
            yield self.record_to_document(record, index=self.index)

    def streaming_bulk_thread(self) -> None:
        """Thread that streams the documents to ES via the bulk api.

        Resources:
            - https://elasticsearch-py.readthedocs.io/en/v8.17.1/helpers.html#elasticsearch.helpers.streaming_bulk
            - https://github.com/elastic/elasticsearch-py/blob/main/elasticsearch/helpers/actions.py#L362
        """

        for _ok, _item in elasticsearch.helpers.streaming_bulk(
            self.es,
            self.document_stream(),
            raise_on_error=True,
            raise_on_exception=True,
            max_retries=self.max_retries,
        ):
            pass

        self.event.set()

    def write(self, record: Record) -> None:
        if self.exception:
            raise self.exception

        self.queue.put(record)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if hasattr(self, "queue"):
            self.queue.put(StopIteration)

        if hasattr(self, "event"):
            self.event.wait()

        if hasattr(self, "es"):
            with suppress(Exception):
                self.es.close()

        if hasattr(self, "exception") and self.exception:
            raise self.exception


class ElasticReader(AbstractReader):
    def __init__(
        self,
        uri: str,
        index: str = "records",
        verify_certs: str | bool = True,
        http_compress: str | bool = True,
        selector: None | Selector | CompiledSelector = None,
        api_key: str | None = None,
        request_timeout: int = 30,
        max_retries: int = 3,
        **kwargs,
    ) -> None:
        self.index = index
        self.uri = uri
        self.selector = selector
        verify_certs = boolean_argument(verify_certs)
        http_compress = boolean_argument(http_compress)
        request_timeout = int(request_timeout)
        max_retries = int(max_retries)

        if not uri.lower().startswith(("http://", "https://")):
            uri = "https://" + uri

        self.es = elasticsearch.Elasticsearch(
            uri,
            verify_certs=verify_certs,
            ssl_show_warn=verify_certs,
            http_compress=http_compress,
            api_key=api_key,
            request_timeout=request_timeout,
            retry_on_timeout=True,
            max_retries=max_retries,
        )

    def __iter__(self) -> Iterator[Record]:
        ctx = get_app_context()
        selector = self.selector
        res = self.es.search(index=self.index)
        log.debug("ElasticSearch returned %u hits", res["hits"]["total"]["value"])
        for hit in res["hits"]["hits"]:
            source = hit["_source"]
            if "_record_metadata" in source:
                _ = source.pop("_record_metadata")
            fields = [(fieldtype_for_value(val, "string"), key) for key, val in source.items()]
            desc = RecordDescriptor("elastic/record", fields)
            obj = desc(**source)
            if match_record_with_context(obj, selector, ctx):
                yield obj

    def close(self) -> None:
        if hasattr(self, "es"):
            self.es.close()


def create_elasticsearch_error_notes(errors: list[dict] | dict, max_notes: int = 0) -> list[str]:
    """
    Convert Elasticsearch Exception errors into pretty formatted notes.

    Resources:
        - https://elasticsearch-py.readthedocs.io/en/v8.17.1/exceptions.html

    Arguments:
        errors: A list of error items from an Elasticsearch exception, or a single error
        max_notes: Maximum number of notes to create. If 0, all errors will be converted into notes.

    Returns:
        A list of formatted error notes.
    """
    if isinstance(errors, dict):
        errors = [errors]

    notes = []
    for idx, error in enumerate(errors, 1):
        # Extract index information
        index = error.get("index", {})
        index_name = index.get("_index", "unknown _index")
        doc_id = index.get("_id", "unknown _id")
        status = index.get("status")

        # Extract error details
        error = index.get("error", {})
        error_type = error.get("type", "unknown error type")
        error_reason = error.get("reason", "unknown reason")

        # Create formatted note
        note_parts = [
            f"Error {idx}, {error_type!r} ({status=}):",
            f"  index: {index_name}",
            f"  document_id: {doc_id}",
            f"  reason: {error_reason}",
        ]

        # Include caused_by information if available
        if caused_by := error.get("caused_by"):
            cause_type = caused_by.get("type")
            cause_reason = caused_by.get("reason")
            note_parts.append(f"  caused_by: {cause_type}, reason: {cause_reason}")

        # Extract the record_descriptor name from the "data" field if possible
        try:
            data = json.loads(index.get("data", "{}"))
            record_metadata = data.pop("_record_metadata", {})
            descriptor = record_metadata.get("descriptor", {})
            if descriptor_name := descriptor.get("name"):
                note_parts.append(f"  descriptor_name: {descriptor_name}")
            if data:
                note_parts.append(f"  data: {json.dumps(data)}")
        except json.JSONDecodeError:
            pass

        notes.append("\n".join(note_parts) + "\n")

        # if max_notes is reached, stop processing and add a final note about remaining errors
        if max_notes > 0 and idx >= max_notes:
            remaining = len(errors) - idx
            if remaining > 0:
                notes.append(f"... and {remaining} more error(s) not shown.")
            break

    return notes
