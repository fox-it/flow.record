from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from flow.record.adapter import AbstractWriter
from flow.record.adapter.csvfile import CsvfileWriter

if TYPE_CHECKING:
    from flow.record.base import Record

__usage__ = """
CSV directory adapter, writes one CSV file per record descriptor (writer only)
---
Write usage: rdump -w csvdirectory://[PATH]?lineterminator=[TERMINATOR]&header=[HEADER]
[PATH]: directory to write CSV files to

Files are created based on the record descriptor name, e.g.:
    filesystem/ntfs/mft/std -> [PATH]/filesystem/ntfs/mft/std.csv

Optional parameters:
    [HEADER]: if set to false, it will not print the CSV header (default: true)
    [TERMINATOR]: line terminator, default is \\r\\n
"""


class CsvdirectoryWriter(AbstractWriter):
    def __init__(self, path: str | Path, **kwargs):
        self.directory = Path(path)
        self.kwargs = kwargs
        self.writers: dict[str, CsvfileWriter] = {}

    def _get_writer(self, r: Record) -> CsvfileWriter:
        desc_name = r._desc.name
        if desc_name not in self.writers:
            file_path = self.directory / f"{desc_name}.csv"
            file_path.parent.mkdir(parents=True, exist_ok=True)
            self.writers[desc_name] = CsvfileWriter(file_path, **self.kwargs)
        return self.writers[desc_name]

    def write(self, r: Record) -> None:
        self._get_writer(r).write(r)

    def flush(self) -> None:
        for writer in self.writers.values():
            writer.flush()

    def close(self) -> None:
        for writer in self.writers.values():
            writer.close()
        self.writers.clear()
