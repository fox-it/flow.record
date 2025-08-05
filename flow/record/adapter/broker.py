from __future__ import annotations

from typing import TYPE_CHECKING

from flow.broker import Publisher, Subscriber
from flow.record.adapter import AbstractReader, AbstractWriter

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record

__usage__ = """
PubSub adapter using flow.broker
---
Write usage: rdump -w broker+tcp://[IP]:[PORT]
Read usage: rdump broker+tcp://[IP]:[PORT] -s True
"""


class BrokerWriter(AbstractWriter):
    publisher = None

    def __init__(self, uri: str, source: str | None = None, classification: str | None = None, **kwargs):
        self.publisher = Publisher(uri, **kwargs)
        self.source = source
        self.classification = classification

    def write(self, r: Record) -> None:
        record = r._replace(
            _source=self.source or r._source,
            _classification=self.classification or r._classification,
        )
        self.publisher.send(record)

    def flush(self) -> None:
        if self.publisher:
            self.publisher.flush()

    def close(self) -> None:
        if self.publisher:
            if hasattr(self.publisher, "stop"):
                # Requires flow.broker >= 1.1.1
                self.publisher.stop()
            else:
                self.publisher.wait()
        self.publisher = None


class BrokerReader(AbstractReader):
    subscriber = None

    def __init__(self, uri: str, name: str | None = None, selector: str | None = None, **kwargs):
        self.subscriber = Subscriber(uri, **kwargs)
        self.subscription = self.subscriber.select(name, str(selector))

    def __iter__(self) -> Iterator[Record]:
        return iter(self.subscription)

    def close(self) -> None:
        if self.subscriber:
            self.subscriber.stop()
        self.subscriber = None
