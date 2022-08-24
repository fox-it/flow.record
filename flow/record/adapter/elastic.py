import logging
import queue
import threading
from typing import Iterator, Union

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
[INDEX]: index to write to or read from
[PROTOCOL]: http or https. Defaults to https when "+[PROTOCOL]" is omitted
"""

log = logging.getLogger(__name__)


class ElasticWriter(AbstractWriter):
    def __init__(self, uri: str, index: str = "records", http_compress: Union[str, bool] = True, **kwargs) -> None:
        self.index = index
        self.uri = uri
        http_compress = str(http_compress).lower() in ("1", "true")
        self.es = elasticsearch.Elasticsearch(uri, http_compress=http_compress)
        self.json_packer = JsonRecordPacker()
        self.queue: queue.Queue[Union[Record, StopIteration]] = queue.Queue()
        self.event = threading.Event()
        self.thread = threading.Thread(target=self.streaming_bulk_thread)
        self.thread.start()

    def record_to_document(self, record: Record, index: str) -> dict:
        """Convert a record to a Elasticsearch compatible document dictionary"""
        rdict = record._asdict()

        # Store record metadata under `_record_metadata`
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
        rdict["_record_metadata"] = rdict_meta

        document = {
            "_index": index,
            "_source": self.json_packer.pack(rdict),
        }
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
        self.es.close()


class ElasticReader(AbstractReader):
    def __init__(
        self,
        uri: str,
        index: str = "records",
        http_compress: Union[str, bool] = True,
        selector: Union[None, Selector, CompiledSelector] = None,
        **kwargs
    ) -> None:
        self.index = index
        self.uri = uri
        self.selector = selector
        http_compress = str(http_compress).lower() in ("1", "true")
        self.es = elasticsearch.Elasticsearch(uri, http_compress=http_compress)

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
        self.es.close()
