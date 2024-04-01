from __future__ import annotations

import logging
import re
from fnmatch import fnmatch
from typing import Iterator

from google.cloud.storage.client import Client
from google.cloud.storage.fileio import BlobReader, BlobWriter

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import Record, RecordAdapter
from flow.record.selector import Selector

__usage__ = """
Google Cloud Storage adapter
---
Read usage: rdump gcs://[BUCKET_ID]/path?project=[PROJECT]
Write usage: rdump -w gcs://[BUCKET_ID]/path?project=[PROJECT]

[BUCKET_ID]: Bucket ID
[path]: Path to read from or write to, supports glob-pattern matching when reading

Optional arguments:
    [PROJECT]: Google Cloud Project ID, If not passed, falls back to the default inferred from the environment.
"""

log = logging.getLogger(__name__)

GLOB_CHARACTERS_RE = r"[\[\]\*\?]"


class GcsReader(AbstractReader):
    def __init__(self, uri: str, *, project: str | None = None, selector: Selector | None = None, **kwargs):
        self.selector = selector
        bucket_name, _, path = uri.partition("/")
        self.gcs = Client(project=project)
        self.bucket = self.gcs.bucket(bucket_name)

        # GCS Doesn't support iterating blobs using a glob pattern, so we have to do that ourselves. To extract the path
        # prefix from the glob-pattern we have to find the first place where the glob starts.
        self.prefix, *glob_pattern = re.split(GLOB_CHARACTERS_RE, path)
        self.pattern = path if glob_pattern else None

    def __iter__(self) -> Iterator[Record]:
        blobs = self.gcs.list_blobs(bucket_or_name=self.bucket, prefix=self.prefix)
        for blob in blobs:
            if blob.size == 0:  # Skip empty files
                continue
            if self.pattern and not fnmatch(blob.name, self.pattern):
                continue
            blobreader = BlobReader(blob)

            # Give the file-like object to RecordAdapter so it will select the right adapter by peeking into the stream
            reader = RecordAdapter(fileobj=blobreader, out=False, selector=self.selector)
            for record in reader:
                yield record

    def close(self) -> None:
        self.gcs.close()


class GcsWriter(AbstractWriter):
    def __init__(self, uri: str, project: str, **kwargs):
        bucket_name, _, path = uri.partition("/")
        self.writer = None

        self.gcs = Client(project=project)
        self.bucket = self.gcs.bucket(bucket_name)

        blob = self.bucket.blob(path)
        self.writer = BlobWriter(blob, ignore_flush=True)
        self.adapter = RecordAdapter(url=path, fileobj=self.writer, out=True, **kwargs)

    def write(self, record: Record) -> None:
        self.adapter.write(record)

    def flush(self) -> None:
        # The underlying adapter may require flushing
        self.adapter.flush()

    def close(self) -> None:
        self.flush()
        self.adapter.close()

        if self.writer:
            self.writer.close()
            self.writer = None
