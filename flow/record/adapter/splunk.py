import json
import logging
import socket
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3

    urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.base import Record
from flow.record.jsonpacker import JsonRecordPacker
from flow.record.utils import to_base64, to_bytes, to_str

__usage__ = """
Splunk output adapter (writer only)
---
Write usage: rdump -w splunk+[PROTOCOL]://[IP]:[PORT]?tag=[TAG]&token=[TOKEN]&sourcetype=[SOURCETYPE]
[PROTOCOL]: Protocol to use for forwarding data. Can be tcp, http or https, defaults to tcp if omitted.
[IP]:[PORT]: ip and port to a splunk instance
[TAG]: optional value to add as "rdtag" output field when writing
[TOKEN]: Authentication token for sending data over HTTP(S)
[SOURCETYPE]: Set sourcetype of data. Defaults to records, but can also be set to JSON.
[SSL_VERIFY]: Whether to verify the server certificate when sending data over HTTP(S). Defaults to True.
"""

log = logging.getLogger(__package__)

# Amount of records to bundle into a single request when sending data over HTTP(S).
RECORD_BUFFER_LIMIT = 20

RESERVED_SPLUNK_FIELDS = set(
    [
        "_indextime",
        "_time",
        "index",
        "punct",
        "source",
        "sourcetype",
        "tag",
        "type",
    ]
)


class Protocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"


class SourceType(Enum):
    JSON = "json"
    RECORDS = "records"


def splunkify_key_value(record: Record, tag: Optional[str] = None) -> str:
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


def splunkify_json(packer: JsonRecordPacker, record: Record, tag: Optional[str] = None) -> str:
    ret = {}

    indexer_fields = {
        ("host", "host"),
        ("host", "hostname"),
        ("time", "ts"),
        ("source", "_source"),
    }

    # When converting a record to json text for splunk, we distinguish between the 'event' (containing the data) and a
    # few other fields that are splunk-specific for indexing. We add those 'indexer_fields' to the return object first.
    for dest_field, source_field in indexer_fields:
        if hasattr(record, source_field):
            val = getattr(record, source_field)
            if val:
                if isinstance(val, datetime):
                    # Convert datetime objects to epoch timestamp for reserved fields.
                    ret[dest_field] = val.timestamp()
                    continue
                ret[dest_field] = to_str(val)

    record_as_dict = packer.pack_obj(record)

    # These fields end up in the 'event', but we have a few reserved field names. If those field names are in the
    # record, we prefix them with 'rd_' (short for record descriptor)
    for field in RESERVED_SPLUNK_FIELDS:
        if field not in record_as_dict.keys():
            continue
        new_field = f"rd_{field}"
        val = record_as_dict[field]
        del record_as_dict[field]
        record_as_dict[new_field] = val

    # almost done, just have to add the tag and the type (i.e the record descriptor's name) to the event.
    record_as_dict["rdtag"] = tag
    record_as_dict["type"] = record._desc.name

    ret["event"] = record_as_dict
    return json.dumps(ret, default=packer.pack_obj)


class SplunkWriter(AbstractWriter):
    sock = None

    def __init__(
        self,
        uri: str,
        tag: Optional[str] = None,
        token: Optional[str] = None,
        sourcetype: Optional[str] = None,
        ssl_verify: bool = True,
        **kwargs,
    ):
        if "://" not in uri:
            uri = f"tcp://{uri}"

        if sourcetype is None:
            log.warning("No sourcetype provided, assuming 'records' sourcetype.")
            sourcetype = SourceType.RECORDS.value

        parsed_url = urlparse(uri)
        url_scheme = parsed_url.scheme.lower()

        self.protocol = next((protocol for protocol in Protocol if protocol.value == url_scheme), None)
        self.sourcetype = next((source for source in SourceType if source.value == sourcetype), None)

        if not self.sourcetype:
            raise ValueError(f"Unsupported source type {sourcetype}.")
        if not self.protocol:
            raise ValueError(f"Unsupported protocol {url_scheme}.")
        if self.protocol == Protocol.TCP and self.sourcetype != SourceType.RECORDS:
            raise ValueError("For sending data to splunk over TCP, only the 'records' sourcetype is allowed.")

        self.host = parsed_url.hostname
        self.port = parsed_url.port
        self.tag = tag
        self.record_buffer = []
        self._warned = False
        self.packer = None

        if self.sourcetype == SourceType.JSON:
            self.packer = JsonRecordPacker(indent=4, pack_descriptors=False)

        if self.protocol == Protocol.TCP:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
            self.sock.connect((self.host, self.port))

        elif self.protocol in [Protocol.HTTP, Protocol.HTTPS]:
            if not HAS_REQUESTS:
                raise ImportError("The requests library is required for sending data over HTTP(S).")

            self.token = token

            # Assume verify=True unless specified otherwise.
            self.verify = not (str(ssl_verify).lower() in ("0", "false"))

            scheme = self.protocol.value
            endpoint = "event" if self.sourcetype != SourceType.RECORDS else "raw"
            port = f":{self.port}" if self.port else ""
            self.url = f"{scheme}://{self.host}{port}/services/collector/{endpoint}?auto_extract_timestamp=true"

            if not self.token:
                raise ValueError("An authorization token is required for the HTTP collector.")

            if not self.token.startswith("Splunk "):
                self.token = "Splunk " + self.token

            if not self.verify:
                log.warning("Certification verification is disabled.")

            self.headers = {
                "Authorization": self.token,
                # A randomized value so that Splunk can loadbalance between different incoming datastreams
                "X-Splunk-Request-Channel": str(uuid.uuid4()),
            }

    def _cache_records_for_http(self, data: Optional[bytes] = None, flush: bool = False) -> Optional[bytes]:
        # It's possible to call this function without any data, purely to flush. Hence this check.
        if data:
            self.record_buffer.append(data)
        if len(self.record_buffer) < RECORD_BUFFER_LIMIT and not flush:
            # Buffer limit not exceeded yet, so we do not return a buffer yet, unless buffer is explicitly flushed.
            return
        buf = b"".join(self.record_buffer)
        if not buf:
            return

        # We're going to be returning a buffer for the writer to send, so we can clear the internal record buffer.
        self.record_buffer.clear()
        return buf

    def _send_http(self, data: Optional[bytes] = None, flush: bool = False) -> None:
        buf = self._cache_records_for_http(data, flush)
        if not buf:
            return
        response = requests.post(self.url, headers=self.headers, verify=self.verify, data=buf)
        if response.status_code != 200:
            raise Exception(f"{response.text} ({response.status_code})")

    def _send_tcp(self, data: bytes) -> None:
        self.sock.sendall(data)

    def write(self, record: Record) -> None:
        if not self._warned and "rdtag" in record._desc.fields:
            self._warned = True
            log.warning(
                "Record has 'rdtag' field which conflicts with the Splunk adapter -- "
                "Splunk output will have duplicate 'rdtag' fields",
            )

        if self.sourcetype == SourceType.RECORDS:
            rec = splunkify_key_value(record, self.tag)
        else:
            rec = splunkify_json(self.packer, record, self.tag)

        # Trail with a newline for line breaking.
        data = to_bytes(rec) + b"\n"

        if self.protocol == Protocol.TCP:
            self._send_tcp(data)
        else:
            self._send_http(data)

    def flush(self) -> None:
        if self.protocol in [Protocol.HTTP, Protocol.HTTPS]:
            self._send_http(flush=True)

    def close(self) -> None:
        # For TCP
        if self.sock:
            self.sock.close()
        self.sock = None
        # For HTTP(S)
        self.flush()


class SplunkReader(AbstractReader):
    def __init__(self, path, selector=None, **kwargs):
        raise NotImplementedError()
