from __future__ import annotations

from typing import TYPE_CHECKING

import bson
from pymongo import MongoClient

from flow import record
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.selector import make_selector

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record.base import Record

__usage__ = """
MongoDB adapter
---
Write usage: rdump -w mongo://[IP]:[PORT]/[DBNAME]/[COLLECTION]
Read usage: rdump mongo://[IP]:[PORT]/[DBNAME]/[COLLECTION]
[IP]:[PORT]: ip and port to a mongodb instance
[DBNAME]: database name to write to or read from
[COLLECTION]: collection to write to or read from
"""


def parse_path(path: str) -> tuple[str, str, str]:
    elements = path.strip("/").split("/", 2)  # max 3 elements
    if len(elements) == 2:
        return "localhost", elements[0], elements[1]
    if len(elements) == 3:
        return tuple(elements)
    raise ValueError("Invalid mongo path")


class MongoWriter(AbstractWriter):
    client = None

    def __init__(self, path: str, key: str | None = None, **kwargs):
        dbhost, dbname, collection = parse_path(path)

        self.key = key
        self.client = MongoClient(host=dbhost)
        self.db = self.client[dbname]
        self.collection = self.db[collection]
        self.coll_descriptors = self.db["_descriptors"]
        self.descriptors = {}

    def write(self, r: Record) -> None:
        d = r._packdict()
        d["_type"] = r._desc.identifier

        if r._desc.identifier not in self.descriptors:
            self.coll_descriptors.find_and_modify(
                {"name": r._desc.identifier}, {"name": r._desc.identifier, "descriptor": r._desc._pack()}, upsert=True
            )

        if self.key:
            # i = self.collection.replace({self.key: d[self.key]}, d) # PyMongo3
            self.collection.find_and_modify({self.key: d[self.key]}, d, upsert=True)  # PyMongo2
        else:
            self.collection.insert(d)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        if self.client:
            self.client.close()
        self.client = None


class MongoReader(AbstractReader):
    client = None

    def __init__(self, path: str, selector: str | None = None, **kwargs):
        dbhost, dbname, collection = parse_path(path)

        self.selector = make_selector(selector)
        self.client = MongoClient(host=dbhost)
        self.db = self.client[dbname]
        self.collection = self.db[collection]
        self.coll_descriptors = self.db["_descriptors"]
        self.descriptors = {}

    def close(self) -> None:
        if self.client:
            self.client.close()
        self.client = None

    def __iter__(self) -> Iterator[Record]:
        desc = None
        for r in self.collection.find():
            if r["_type"] not in self.descriptors:
                packed_desc = self.coll_descriptors.find({"name": r["_type"]})[0]["descriptor"]
                self.descriptors[r["_type"]] = record.RecordDescriptor(*packed_desc)

            desc = self.descriptors[r["_type"]]

            del r["_id"]
            del r["_type"]

            for k in list(r.keys()):
                if isinstance(r[k], bson.int64.Int64):
                    r[k] = int(r[k])

            obj = desc(**r)
            if not self.selector or self.selector.match(obj):
                yield obj
