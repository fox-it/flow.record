from __future__ import annotations

import hashlib
import logging
import queue
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
            uri = "http://" + uri

        self.queue: queue.Queue[Record | StopIteration] = queue.Queue(maxsize=queue_size)
        self.event = threading.Event()
        self.exception: Exception | None = None
        threading.excepthook = self.excepthook

        self.es = elasticsearch.Elasticsearch(
            uri,
            verify_certs=verify_certs,
            http_compress=http_compress,
            api_key=api_key,
            request_timeout=request_timeout,
            retry_on_timeout=True,
            max_retries=self.max_retries,
        )

        self.json_packer = JsonRecordPacker()

        self.thread = threading.Thread(target=self.streaming_bulk_thread)
        self.thread.start()

        if not verify_certs:
            # Disable InsecureRequestWarning of urllib3, caused by the verify_certs flag.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.metadata_fields = {}
        for arg_key, arg_val in kwargs.items():
            if arg_key.startswith("_meta_"):
                self.metadata_fields[arg_key[6:]] = arg_val

    def excepthook(self, exc: threading.ExceptHookArgs, *args, **kwargs) -> None:
        self.exception = getattr(exc, "exc_value", exc)
        self.exception = enrich_elastic_exception(self.exception)
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
            uri = "http://" + uri

        self.es = elasticsearch.Elasticsearch(
            uri,
            verify_certs=verify_certs,
            http_compress=http_compress,
            api_key=api_key,
            request_timeout=request_timeout,
            retry_on_timeout=True,
            max_retries=max_retries,
        )

        if not verify_certs:
            # Disable InsecureRequestWarning of urllib3, caused by the verify_certs flag.
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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


def enrich_elastic_exception(exception: Exception) -> Exception:
    """Extend the exception with error information from Elastic.

    Resources:
        - https://elasticsearch-py.readthedocs.io/en/v8.17.1/exceptions.html
    """
    errors = set()
    if hasattr(exception, "errors"):
        try:
            for error in exception.errors:
                index_dict = error.get("index", {})
                status = index_dict.get("status")
                error_dict = index_dict.get("error", {})
                error_type = error_dict.get("type")
                error_reason = error_dict.get("reason", "")

                errors.add(f"({status} {error_type} {error_reason})")
        except Exception:
            errors.add("unable to extend errors")

    # append errors to original exception message
    error_str = ", ".join(errors)
    original_message = exception.args[0] if exception.args else ""
    new_message = f"{original_message} {error_str}"
    exception.args = (new_message, *exception.args[1:])

    return exception
