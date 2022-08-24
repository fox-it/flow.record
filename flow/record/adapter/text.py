from flow.record import open_path
from flow.record.utils import is_stdout
from flow.record.adapter import AbstractWriter

__usage__ = """
Textual output adapter, similar to `repr()` (writer only)
---
Write usage: rdump -w text://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""

REPLACE_LIST = [
    (r"\r", "\r"),
    (r"\n", "\n"),
    (r"\t", "\t"),
]


class DefaultMissing(dict):
    def __missing__(self, key):
        return key.join("{}")


class TextWriter(AbstractWriter):
    """Records are printed as textual representation with repr() or using `format_spec`."""

    fp = None

    def __init__(self, path, flush=True, format_spec=None, **kwargs):
        self.fp = open_path(path, "wb")
        self.auto_flush = flush
        self.format_spec = format_spec

        # Allow some special characters in format template
        if self.format_spec:
            for old, new in REPLACE_LIST:
                self.format_spec = self.format_spec.replace(old, new)

    def write(self, rec):
        if self.format_spec:
            buf = self.format_spec.format_map(DefaultMissing(rec._asdict()))
        else:
            buf = repr(rec)
        self.fp.write(buf.encode() + b"\n")

        # because stdout is usually line buffered we force flush here if wanted
        if self.auto_flush:
            self.flush()

    def flush(self):
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
