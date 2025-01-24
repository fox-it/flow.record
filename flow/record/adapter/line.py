from __future__ import annotations

from functools import lru_cache

from flow.record import Record, RecordDescriptor, open_path_or_stream
from flow.record.adapter import AbstractWriter
from flow.record.utils import is_stdout

__usage__ = """
Line output format adapter (writer only)
---
Write usage: rdump -w line://[PATH]?verbose=[VERBOSE]
[PATH]: path to file. Leave empty or "-" to output to stdout

Optional arguments:
    [VERBOSE]: Also show fieldtype in line output (default: False)
"""


@lru_cache(maxsize=1024)
def field_types_for_record_descriptor(desc: RecordDescriptor) -> dict[str, str]:
    """Return dictionary of fieldname -> fieldtype for given RecordDescriptor.

    Args:
        desc: RecordDescriptor to get fieldtypes for
    Returns:
        Dictionary of fieldname -> fieldtype
    """
    return {fname: fieldset.typename for fname, fieldset in desc.get_all_fields().items()}


class LineWriter(AbstractWriter):
    """Prints all fields and values of the Record on a separate line."""

    fp = None

    def __init__(
        self,
        path: str,
        *,
        fields: list[str] | str | None = None,
        exclude: list[str] | str | None = None,
        verbose: bool = False,
        **kwargs,
    ):
        self.fp = open_path_or_stream(path, "wb")
        self.count = 0
        self.fields = fields
        self.exclude = exclude
        self.verbose = verbose
        if isinstance(self.fields, str):
            self.fields = self.fields.split(",")
        if isinstance(self.exclude, str):
            self.exclude = self.exclude.split(",")

    def write(self, rec: Record) -> None:
        rdict = rec._asdict(fields=self.fields, exclude=self.exclude)
        rdict_types = field_types_for_record_descriptor(rec._desc) if self.verbose else None

        self.count += 1
        self.fp.write(f"--[ RECORD {self.count} ]--\n".encode())
        if rdict:
            # also account for extra characters for fieldtype and whitespace + parenthesis
            width = max(len(k + rdict_types[k]) for k in rdict) + 3 if rdict_types else max(len(k) for k in rdict)
            fmt = f"{{:>{width}}} = {{}}\n"
        for key, value in rdict.items():
            if rdict_types:
                key = f"{key} ({rdict_types[key]})"
            self.fp.write(fmt.format(key, value).encode(errors="surrogateescape"))

    def flush(self) -> None:
        if self.fp:
            self.fp.flush()

    def close(self) -> None:
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
