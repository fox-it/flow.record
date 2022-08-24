from flow.record.adapter import AbstractWriter, AbstractReader
from flow.broker import Publisher, Subscriber

__usage__ = """
PubSub adapter using flow.broker
---
Write usage: rdump -w broker+tcp://[IP]:[PORT]
Read usage: rdump broker+tcp://[IP]:[PORT] -s True
"""


class BrokerWriter(AbstractWriter):
    publisher = None

    def __init__(self, uri, source=None, classification=None, **kwargs):
        self.publisher = Publisher(uri, **kwargs)
        self.source = source
        self.classification = classification

    def write(self, r):
        record = r._replace(
            _source=self.source or r._source,
            _classification=self.classification or r._classification,
        )
        self.publisher.send(record)

    def flush(self):
        if self.publisher:
            self.publisher.flush()

    def close(self):
        if self.publisher:
            if hasattr(self.publisher, "stop"):
                # Requires flow.broker >= 1.1.1
                self.publisher.stop()
            else:
                self.publisher.wait()
        self.publisher = None


class BrokerReader(AbstractReader):
    subscriber = None

    def __init__(self, uri, name=None, selector=None, **kwargs):
        self.subscriber = Subscriber(uri, **kwargs)
        self.subscription = self.subscriber.select(name, str(selector))

    def __iter__(self):
        return iter(self.subscription)

    def close(self):
        if self.subscriber:
            self.subscriber.stop()
        self.subscriber = None
