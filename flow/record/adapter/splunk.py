import socket
import logging

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.utils import to_str, to_bytes, to_base64

__usage__ = """
Splunk output adapter (writer only)
---
Write usage: rdump -w splunk://[IP]:[PORT]?tag=[TAG]
[IP]:[PORT]: ip and port to a splunk instance
[TAG]: optional value to add as "rdtag" output field when writing
"""

log = logging.getLogger(__package__)

RESERVED_SPLUNK_FIELDS = set(
    [
        "_indextime",
        "_time",
        "index",
        "punct",
        "source",
        "sourcetype",
        "tag",
    ]
)


def splunkify(record, tag=None):
    ret = []

    ret.append(f'type="{record._desc.name}"')

    if tag is None:
        ret.append("rdtag=None")
    else:
        ret.append(f'rdtag="{tag}"')

    for field in record._desc.fields:
        val = getattr(record, field)
        if val is None:
            ret.append(f"{field}=None")
        else:
            val = to_base64(val) if isinstance(val, bytes) else to_str(val)
            val = val.replace("\\", "\\\\").replace('"', '\\"')
            if field in RESERVED_SPLUNK_FIELDS:
                field = f"rd_{field}"
            ret.append(f'{field}="{val}"')

    return " ".join(ret)


class SplunkWriter(AbstractWriter):
    sock = None

    def __init__(self, path, tag=None, **kwargs):
        p = path.strip("/").split("/")
        host, port = p[0].split(":")
        port = int(port)

        self.tag = tag
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
        self.sock.connect((host, port))
        self.descriptors = {}
        self._warned = False

    def write(self, record):
        if not self._warned and "rdtag" in record._desc.fields:
            self._warned = True
            log.warning(
                "Record has 'rdtag' field which conflicts with the Splunk adapter -- "
                "Splunk output will have duplicate 'rdtag' fields",
            )
        rec = splunkify(record, tag=self.tag)
        data = to_bytes(rec) + b"\n"
        self.sock.sendall(data)

    def flush(self):
        pass

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None


class SplunkReader(AbstractReader):
    def __init__(self, path, selector=None, **kwargs):
        raise NotImplementedError()
