import threading
import logging
import queue

import elasticsearch
import elasticsearch.helpers

from flow.record.adapter import AbstractWriter, AbstractReader
from flow.record import JsonRecordPacker, RecordDescriptor
from flow.record.fieldtypes import fieldtype_for_value

log = logging.getLogger(__name__)


class ElasticWriter(AbstractWriter):
    def __init__(self, uri, index="records", http_compress=True, **kwargs):
        self.index = index
        self.uri = uri
        http_compress = str(http_compress).lower() in ("1", "true")
        self.es = elasticsearch.Elasticsearch(uri, http_compress=http_compress)
        self.json_packer = JsonRecordPacker()
        self.queue = queue.Queue()
        self.event = threading.Event()
        self.thread = threading.Thread(target=self.streaming_bulk_thread).start()

    def record_to_document(self, record, index):
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

    def document_stream(self):
        """Generator of record documents on the Queue"""
        while True:
            record = self.queue.get()
            if record == StopIteration:
                break
            yield self.record_to_document(record, index=self.index)

    def streaming_bulk_thread(self):
        """Thread that streams the documents to ES via the bulk api"""
        for ok, item in elasticsearch.helpers.streaming_bulk(
            self.es,
            self.document_stream(),
            raise_on_error=False,
            raise_on_exception=False,
        ):
            if not ok:
                log.error(f"Failed to insert {item}")
        self.event.set()

    def write(self, r):
        self.queue.put_nowait(r)

    def flush(self):
        pass

    def close(self):
        self.queue.put(StopIteration)
        self.event.wait()
        self.es.close()


class ElasticReader(AbstractReader):
    def __init__(self, uri, index="records", http_compress=True, selector=None, **kwargs):
        self.index = index
        self.uri = uri
        self.selector = selector
        http_compress = str(http_compress).lower() in ("1", "true")
        self.es = elasticsearch.Elasticsearch(uri, http_compress=http_compress)

    def __iter__(self):
        res = self.es.search(index=self.index)
        log.debug(f"ElasticSearch returned {res['hits']['total']['value']} hits")
        for hit in res["hits"]["hits"]:
            source = hit["_source"]
            if "_record_metadata" in source:
                _ = source.pop("_record_metadata")
            fields = [(fieldtype_for_value(val, "string"), key) for key, val in source.items()]
            desc = RecordDescriptor("elastic/record", fields)
            obj = desc(**source)
            if not self.selector or self.selector.match(obj):
                yield obj

    def close(self):
        self.es.close()
