import elasticsearch
import elasticsearch.helpers

from flow.record.adapter import AbstractWriter, AbstractReader


def index_stream(index, it):
    for r in it:
        d = r.dict()
        if "Value" in d:
            del d["Value"]

        yield {
            "_index": index,
            "_type": "event_" + str(d["EventID"]),
            "_source": d,
        }


class ElasticWriter(AbstractWriter):

    def __init__(self, index, **kwargs):
        self.index = index

        self.es = elasticsearch.Elasticsearch()

    # def writeblob(self, src):
    #   count = elasticsearch.helpers.bulk(es, index_stream("logtest", src))

    def write(self, r):
        self.es.index({"_index": self.index, "_type": r._desc.name, "_source": r.dict()})

    def flush(self):
        pass

    def close(self):
        pass


class ElasticReader(AbstractReader):

    def __iter__(self, r, **kwargs):
        raise NotImplementedError()
