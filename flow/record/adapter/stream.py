from flow import record
from flow.record.utils import is_stdout
from flow.record.adapter import AbstractReader, AbstractWriter

__usage__ = """
Save records as records to file: rdump -w stream://path/to/file.rec
Write records as records to stdout: rdump -w stream://
---
Read records to an output type: rdump path/to/file.rec -w {outputype}://
"""


class StreamWriter(AbstractWriter):
    fp = None
    stream = None

    def __init__(self, path, clobber=True, **kwargs):
        self.fp = record.open_path(path, "wb", clobber=clobber)
        self.stream = record.RecordOutput(self.fp)

    def write(self, r):
        self.stream.write(r)

    def flush(self):
        if self.stream and hasattr(self.stream, "flush"):
            self.stream.flush()
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.stream:
            self.stream.close()
        self.stream = None

        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class StreamReader(AbstractReader):
    fp = None
    stream = None

    def __init__(self, path, selector=None, **kwargs):
        self.fp = record.open_path(path, "rb")
        self.stream = record.RecordStreamReader(self.fp, selector=selector)

    def __iter__(self):
        return iter(self.stream)

    def close(self):
        if self.stream:
            self.stream.close()
        self.stream = None

        if self.fp:
            self.fp.close()
        self.fp = None
