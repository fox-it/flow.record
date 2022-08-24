from __future__ import absolute_import

import sys
from csv import DictWriter

from flow.record import open_path
from flow.record.utils import is_stdout
from flow.record.adapter import AbstractWriter

__usage__ = """
Comma-separated values (CSV) adapter
---
Write usage: rdump -w csvfile://[PATH]
Read usage: rdump csvfile://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""


class CsvfileWriter(AbstractWriter):
    fp = None

    def __init__(self, path, fields=None, exclude=None, **kwargs):
        mode = "w"
        if sys.version_info[0] < 3:
            mode = "wb"
        self.fp = open_path(path, mode)
        self.desc = None
        self.writer = None
        self.fields = fields
        self.exclude = exclude
        if isinstance(self.fields, str):
            self.fields = self.fields.split(",")
        if isinstance(self.exclude, str):
            self.exclude = self.exclude.split(",")

    def write(self, r):
        rdict = r._asdict(fields=self.fields, exclude=self.exclude)
        if not self.desc or self.desc != r._desc:
            self.desc = r._desc
            self.writer = DictWriter(self.fp, rdict)
            self.writer.writeheader()
        self.writer.writerow(rdict)

    def flush(self):
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
