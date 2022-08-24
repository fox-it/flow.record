import openpyxl

from flow import record
from flow.record.utils import is_stdout
from flow.record.selector import make_selector
from flow.record.adapter import AbstractWriter, AbstractReader

__usage__ = """
Microsoft Excel spreadsheet adapter
---
Write usage: rdump -w xlsx://[PATH]
Read usage: rdump xlsx://[PATH]
[PATH]: path to file. Leave empty or "-" to output to stdout
"""


class XlsxWriter(AbstractWriter):
    fp = None
    wb = None

    def __init__(self, path, **kwargs):
        self.fp = record.open_path(path, "wb")
        self.wb = openpyxl.Workbook()
        self.ws = self.wb.active
        self.desc = None
        # self.ws.title = "Records"

    def write(self, r):
        if not self.desc:
            self.desc = r._desc
            self.ws.append(r._desc.fields)

        self.ws.append(r._asdict().values())

    def flush(self):
        if self.wb:
            self.wb.save(self.fp)

    def close(self):
        if self.wb:
            self.wb.close()
        self.wb = None

        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None


class XlsxReader(AbstractReader):
    fp = None

    def __init__(self, path, selector=None, **kwargs):
        self.selector = make_selector(selector)
        self.fp = record.open_path(path, "rb")
        self.desc = None
        self.wb = openpyxl.load_workbook(self.fp)
        self.ws = self.wb.active

    def close(self):
        if self.fp:
            self.fp.close()
        self.fp = None

    def __iter__(self):
        desc = None
        for row in self.ws.rows:
            if not desc:
                desc = record.RecordDescriptor([col.value.replace(" ", "_").lower() for col in row])
                continue

            obj = desc(*[col.value for col in row])
            if not self.selector or self.selector.match(obj):
                yield obj
