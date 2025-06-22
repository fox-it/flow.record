#!/usr/bin/env pypy
from __future__ import annotations

import sys
from datetime import datetime, timezone

import net.ipv4
import record
from fileprocessing import DirectoryProcessor

UTC_TIMEZONE = timezone.utc


def ts(s: float) -> datetime:
    return datetime.fromtimestamp(float(s), tz=UTC_TIMEZONE)


def ip(s: str) -> net.ipv4.Address:
    return net.ipv4.Address(s)


class SeparatedFile:
    fp = None
    seperator = None
    format = None

    def __init__(self, fp: list[str], seperator: str | None, format: list[tuple]):
        self.fp = fp
        self.seperator = seperator
        self.format = format

    def __iter__(self):
        desc = record.RecordDescriptor([i[0] for i in PASSIVEDNS_FORMAT])
        recordtype = desc.recordType

        for line in self.fp:
            p = line.strip().split(self.seperator)

            r = {}
            for i in range(len(self.format)):
                field = self.format[i]

                v = p[i]
                if field[1]:
                    v = field[1](v)

                r[field[0]] = v

            yield recordtype(**r)


def PassiveDnsFile(fp: list[str]) -> SeparatedFile:
    return SeparatedFile(fp, "||", PASSIVEDNS_FORMAT)


PASSIVEDNS_FORMAT = [
    ("ts", ts),
    ("src", ip),
    ("dst", ip),
    ("family", None),
    ("query", None),
    ("query_type", None),
    ("result", None),
    ("ttl", int),
    ("x", None),
]


def main() -> None:
    rs = record.RecordOutput(sys.stdout)
    for r in DirectoryProcessor(sys.argv[1], PassiveDnsFile, r"\.log\.gz"):
        rs.write(r)


if __name__ == "__main__":
    main()
