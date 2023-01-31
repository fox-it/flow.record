from __future__ import absolute_import

import csv
import sys

from flow.record import RecordDescriptor
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.selector import make_selector
from flow.record.utils import is_stdout

__usage__ = """
Comma-separated values (CSV) adapter
---
Write usage: rdump -w csvfile://[PATH]?lineterminator=[TERMINATOR]
Read usage: rdump csvfile://[PATH]?fields=[FIELDS]
[PATH]: path to file. Leave empty or "-" to output to stdout
[TERMINATOR]: line terminator, default is \\r\\n
[FIELDS]: comma-separated list of CSV fields (in case of missing CSV header)
"""


class CsvfileWriter(AbstractWriter):
    fp = None

    def __init__(self, path, fields=None, exclude=None, lineterminator=None, **kwargs):
        if path in (None, "", "-"):
            self.fp = sys.stdout
        else:
            self.fp = open(path, "w", newline="")
        self.lineterminator = lineterminator or "\r\n"
        for r, n in ((r"\r", "\r"), (r"\n", "\n"), (r"\t", "\t")):
            self.lineterminator = self.lineterminator.replace(r, n)
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
            self.writer = csv.DictWriter(self.fp, rdict, lineterminator=self.lineterminator)
            self.writer.writeheader()
        self.writer.writerow(rdict)

    def flush(self):
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class CsvfileReader(AbstractReader):
    fp = None

    def __init__(self, path, selector=None, fields=None, **kwargs):
        self.selector = make_selector(selector)
        if path in (None, "", "-"):
            self.fp = sys.stdin
        else:
            self.fp = open(path, "r", newline="")
        self.reader = csv.reader(self.fp)

        if isinstance(fields, str):
            # parse fields from fields argument (comma-separated string)
            self.fields = fields.split(",")
        else:
            # parse fields from first CSV row
            self.fields = next(self.reader)

        # Create RecordDescriptor from fields
        self.desc = RecordDescriptor("csv/reader", [("string", col) for col in self.fields])

    def close(self):
        if self.fp:
            self.fp.close()
        self.fp = None

    def __iter__(self):
        for row in self.reader:
            record = self.desc(*row)
            if not self.selector or self.selector.match(record):
                yield record
