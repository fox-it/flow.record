from __future__ import annotations

import csv
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from flow.record import RecordDescriptor
from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import Record, normalize_fieldname
from flow.record.selector import make_selector
from flow.record.utils import boolean_argument, is_stdout

if TYPE_CHECKING:
    from collections.abc import Iterator

__usage__ = """
Comma-separated values (CSV) adapter
---
Write usage: rdump -w csvfile://[PATH]?lineterminator=[TERMINATOR]&header=[HEADER]
Read usage: rdump csvfile://[PATH]?fields=[FIELDS]
[PATH]: path to file. Leave empty or "-" to output to stdout

Optional parameters:
    [HEADER]: if set to false, it will not print the CSV header (default: true)
    [TERMINATOR]: line terminator, default is \\r\\n
    [FIELDS]: comma-separated list of CSV fields (in case of missing CSV header)
"""


class CsvfileWriter(AbstractWriter):
    def __init__(
        self,
        path: str | Path | None,
        fields: str | list[str] | None = None,
        exclude: str | list[str] | None = None,
        lineterminator: str = "\r\n",
        header: str = "true",
        **kwargs,
    ):
        self.fp = None
        if path in (None, "", "-"):
            self.fp = sys.stdout
        else:
            self.fp = Path(path).open("w", newline="")  # noqa: SIM115
        self.lineterminator = lineterminator
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
        self.header = boolean_argument(header)

    def write(self, r: Record) -> None:
        rdict = r._asdict(fields=self.fields, exclude=self.exclude)
        if not self.desc or self.desc != r._desc:
            self.desc = r._desc
            self.writer = csv.DictWriter(self.fp, rdict, lineterminator=self.lineterminator)
            if self.header:
                # Write header only if it is requested
                self.writer.writeheader()
        self.writer.writerow(rdict)

    def flush(self) -> None:
        if self.fp:
            self.fp.flush()

    def close(self) -> None:
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class CsvfileReader(AbstractReader):
    def __init__(
        self, path: str | Path | None, selector: str | None = None, fields: str | list[str] | None = None, **kwargs
    ):
        self.fp = None
        self.selector = make_selector(selector)
        if path in (None, "", "-"):
            self.fp = sys.stdin
        else:
            self.fp = Path(path).open("r", newline="")  # noqa: SIM115

        self.dialect = "excel"
        if self.fp.seekable():
            self.dialect = csv.Sniffer().sniff(self.fp.read(1024))
            self.fp.seek(0)
        self.reader = csv.reader(self.fp, dialect=self.dialect)

        if isinstance(fields, str):
            # parse fields from fields argument (comma-separated string)
            self.fields = fields.split(",")
        else:
            # parse fields from first CSV row
            self.fields = next(self.reader)

        # clean field names
        self.fields = [normalize_fieldname(col) for col in self.fields]

        # Create RecordDescriptor from fields, skipping fields starting with "_" (reserved for internal use)
        self.desc = RecordDescriptor("csv/reader", [("string", col) for col in self.fields if not col.startswith("_")])

    def close(self) -> None:
        if self.fp:
            self.fp.close()
        self.fp = None

    def __iter__(self) -> Iterator[Record]:
        for row in self.reader:
            rdict = dict(zip(self.fields, row))
            record = self.desc.init_from_dict(rdict)
            if not self.selector or self.selector.match(record):
                yield record
