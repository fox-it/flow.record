from flow.record.adapter import AbstractWriter
from flow.record import open_path
from flow.record.utils import is_stdout

__usage__ = """
Line output format adapter (writer only)
---
Write usage: rdump -w line://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""


class LineWriter(AbstractWriter):
    """Prints all fields and values of the Record on a separate line."""

    fp = None

    def __init__(self, path, fields=None, exclude=None, **kwargs):
        self.fp = open_path(path, "wb")
        self.count = 0
        self.fields = fields
        self.exclude = exclude
        if isinstance(self.fields, str):
            self.fields = self.fields.split(",")
        if isinstance(self.exclude, str):
            self.exclude = self.exclude.split(",")

    def write(self, rec):
        rdict = rec._asdict(fields=self.fields, exclude=self.exclude)
        self.count += 1
        self.fp.write("--[ RECORD {} ]--\n".format(self.count).encode())
        if rdict:
            fmt = "{{:>{width}}} = {{}}\n".format(width=max(len(k) for k in rdict))
        for (key, value) in rdict.items():
            self.fp.write(fmt.format(key, value).encode())

    def flush(self):
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
