from flow.record import open_path_or_stream
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


class LineWriter(AbstractWriter):
    """Prints all fields and values of the Record on a separate line."""

    fp = None

    def __init__(self, path, *, fields=None, exclude=None, verbose=False, **kwargs):
        self.fp = open_path_or_stream(path, "wb")
        self.count = 0
        self.fields = fields
        self.exclude = exclude
        self.verbose = verbose
        if isinstance(self.fields, str):
            self.fields = self.fields.split(",")
        if isinstance(self.exclude, str):
            self.exclude = self.exclude.split(",")

    def write(self, rec):
        rdict = rec._asdict(fields=self.fields, exclude=self.exclude)
        rdict_types = None
        if self.verbose:
            rdict_types = {fname: fieldset.typename for fname, fieldset in rec._desc.get_all_fields().items()}

        self.count += 1
        self.fp.write("--[ RECORD {} ]--\n".format(self.count).encode())
        if rdict:
            if rdict_types:
                # also account for extra characters for fieldtype and whitespace + parenthesis
                width = max(len(k + rdict_types[k]) for k in rdict) + 3
            else:
                width = max(len(k) for k in rdict)
            fmt = "{{:>{width}}} = {{}}\n".format(width=width)
        for key, value in rdict.items():
            if rdict_types:
                key = f"{key} ({rdict_types[key]})"
            self.fp.write(fmt.format(key, value).encode())

    def flush(self):
        if self.fp:
            self.fp.flush()

    def close(self):
        if self.fp and not is_stdout(self.fp):
            self.fp.close()
        self.fp = None
