from __future__ import annotations

import hashlib
import logging
import queue
import threading
from typing import Iterator

import elasticsearch
import elasticsearch.helpers

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import Record, RecordDescriptor
from flow.record.fieldtypes import fieldtype_for_value
from flow.record.jsonpacker import JsonRecordPacker
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
  [INDEX]: name of the index to use (default: records)
  [VERIFY_CERTS]: verify certs of Elasticsearch instance (default: True)
  [HASH_RECORD]: make record unique by hashing record [slow] (default: False)
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
        **kwargs,
    ) -> None:
        self.index = index
        self.uri = uri
        verify_certs = str(verify_certs).lower() in ("1", "true")
        http_compress = str(http_compress).lower() in ("1", "true")
        self.hash_record = str(hash_record).lower() in ("1", "true")

        if not uri.lower().startswith(("http://", "https://")):
            uri = "http://" + uri

        self.es = elasticsearch.Elasticsearch(
            uri,
            verify_certs=verify_certs,
            http_compress=http_compress,
            api_key=api_key,
        )

        self.json_packer = JsonRecordPacker()
        self.queue: queue.Queue[Record | StopIteration] = queue.Queue()
        self.event = threading.Event()
        self.thread = threading.Thread(target=self.streaming_bulk_thread)
        self.thread.start()
        self.exception: Exception | None = None
        threading.excepthook = self.excepthook

        if not verify_certs:
            # Disable InsecureRequestWarning of urllib3, caused by the verify_certs flag.
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.metadata_fields = {}
        for arg_key, arg_val in kwargs.items():
            if arg_key.startswith("_meta_"):
                self.metadata_fields[arg_key[6:]] = arg_val

    def excepthook(self, exc: threading.ExceptHookArgs, *args, **kwargs) -> None:
        log.error("Exception in thread: %s", exc.exc_value.message)
        self.exception = exc.exc_value
        self.event.set()
        self.close()

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
            yield self.record_to_document(record, index=self.index)

    def streaming_bulk_thread(self) -> None:
        """Thread that streams the documents to ES via the bulk api"""

        for ok, item in elasticsearch.helpers.streaming_bulk(
            self.es,
            self.document_stream(),
            raise_on_error=False,
            raise_on_exception=False,
        ):
            if not ok:
                log.error("Failed to insert %r", item)

        self.event.set()

    def write(self, record: Record) -> None:
        self.queue.put_nowait(record)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.queue.put(StopIteration)
        self.event.wait()
        if hasattr(self, "es"):
            self.es.close()

        if self.exception:
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
        **kwargs,
    ) -> None:
        self.index = index
        self.uri = uri
        self.selector = selector
        verify_certs = str(verify_certs).lower() in ("1", "true")
        http_compress = str(http_compress).lower() in ("1", "true")

        if not uri.lower().startswith(("http://", "https://")):
            uri = "http://" + uri

        self.es = elasticsearch.Elasticsearch(
            uri,
            verify_certs=verify_certs,
            http_compress=http_compress,
            api_key=api_key,
        )

        if not verify_certs:
            # Disable InsecureRequestWarning of urllib3, caused by the verify_certs flag.
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def __iter__(self) -> Iterator[Record]:
        res = self.es.search(index=self.index)
        log.debug("ElasticSearch returned %u hits", res["hits"]["total"]["value"])
        for hit in res["hits"]["hits"]:
            source = hit["_source"]
            if "_record_metadata" in source:
                _ = source.pop("_record_metadata")
            fields = [(fieldtype_for_value(val, "string"), key) for key, val in source.items()]
            desc = RecordDescriptor("elastic/record", fields)
            obj = desc(**source)
            if not self.selector or self.selector.match(obj):
                yield obj

    def close(self) -> None:
        if hasattr(self, "es"):
            self.es.close()
