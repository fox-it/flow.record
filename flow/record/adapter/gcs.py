import logging
import re
from fnmatch import fnmatch
from typing import Iterator, Union

from google.cloud.storage.client import Client
from google.cloud.storage.fileio import BlobReader, BlobWriter

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import Record, RecordAdapter
from flow.record.selector import CompiledSelector, Selector

__usage__ = """
Google Cloud Storage adapter
---
Read usage: rdump gcs://[BUCKET_ID]/path?project_id=[PROJECT_ID]
[PROJECT_ID]: Google Cloud Project ID
[BUCKET_ID]: Bucket ID
[path]: Path to look for files, with support for glob-pattern matching

Write usage: rdump gcs://[BUCKET_ID]/path?project_id=[PROJECT_ID]
[PROJECT_ID]: Google Cloud Project ID
[BUCKET_ID]: Bucket ID
[path]: Path to write records to
"""

log = logging.getLogger(__name__)

GLOB_CHARACTERS_RE = r"[\[\]\*\?]"


class GcsReader(AbstractReader):
    def __init__(self, uri: str, project: str, selector: Union[None, Selector, CompiledSelector] = None, **kwargs):
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
        # https://cloud.google.com/python/docs/reference/storage/latest/google.cloud.storage.fileio.BlobWriter)
        # Flushing without closing is not supported by the remote service and therefore calling it on this class
        # normally results in io.UnsupportedOperation. However, that behavior is incompatible with some consumers and
        # wrappers of fileobjects in Python.
        pass

    def close(self) -> None:
        if self.writer:
            self.writer.close()
            self.writer = None
