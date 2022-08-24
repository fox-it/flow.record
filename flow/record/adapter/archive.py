from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.stream import RecordArchiver

__usage__ = """
Record archiver adapter, writes records to YYYY/mm/dd directories (writer only)
---
Write usage: rdump -w archive://[PATH]
[PATH]: path to folder
"""


class ArchiveWriter(AbstractWriter):
    writer = None

    def __init__(self, path, **kwargs):
        self.path = path

        path_template = kwargs.get("path_template")
        name = kwargs.get("name")

        self.writer = RecordArchiver(self.path, path_template=path_template, name=name)

    def write(self, r):
        self.writer.write(r)

    def flush(self):
        # RecordArchiver already flushes after every write
        pass

    def close(self):
        if self.writer:
            self.writer.close()
        self.writer = None


class ArchiveReader(AbstractReader):
    def __init__(self, path, **kwargs):
        raise NotImplementedError
