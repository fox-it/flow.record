from __future__ import annotations

import json
import logging
import socket
import uuid
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING
from urllib.parse import urlparse

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

from flow.record.adapter import AbstractReader, AbstractWriter
from flow.record.jsonpacker import JsonRecordPacker
from flow.record.utils import boolean_argument, to_base64, to_bytes, to_str

if TYPE_CHECKING:
    from flow.record.base import Record

__usage__ = """
Splunk output adapter (writer only)
---
Write usage: rdump -w splunk+[PROTOCOL]://[IP]:[PORT]?tag=[TAG]&token=[TOKEN]&sourcetype=[SOURCETYPE]
[PROTOCOL]: Protocol to use for forwarding data. Can be tcp, http or https, defaults to tcp if omitted.
[IP]:[PORT]: ip and port to a splunk instance
[TAG]: optional value to add as "rdtag" output field when writing
[TOKEN]: Authentication token for sending data over HTTP(S)
[SOURCETYPE]: Set sourcetype of data. Defaults to records, but can also be set to JSON.
[SSL_VERIFY]: Whether to verify the server certificate when sending data over HTTPS. Defaults to True.
"""

log = logging.getLogger(__package__)

# Amount of records to bundle into a single request when sending data over HTTP(S).
RECORD_BUFFER_LIMIT = 20

# List of reserved splunk fields that do not start with an `_`, as those will be escaped anyway.
# See: https://docs.splunk.com/Documentation/Splunk/9.2.1/Data/Aboutdefaultfields
RESERVED_SPLUNK_FIELDS = {
    "host",
    "index",
    "linecount",
    "punct",
    "source",
    "sourcetype",
    "splunk_server",
    "timestamp",
}

RESERVED_SPLUNK_APP_FIELDS = {
    "tag",
    "type",
}

RESERVED_RDUMP_FIELDS = {
    "rdtag",
    "rdtype",
}

RESERVED_FIELDS = RESERVED_SPLUNK_FIELDS.union(RESERVED_SPLUNK_APP_FIELDS.union(RESERVED_RDUMP_FIELDS))

ESCAPE = "rd_"


class Protocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"


class SourceType(Enum):
    JSON = "json"
    RECORDS = "records"


def escape_field_name(field: str) -> str:
    if field.startswith(("_", ESCAPE)) or field in RESERVED_FIELDS:
        field = f"{ESCAPE}{field}"
    return field


def record_to_splunk_kv_line(record: Record, tag: str | None = None) -> str:
    ret = []

    ret.append(f'rdtype="{record._desc.name}"')

    if tag is None:
        ret.append("rdtag=None")
    else:
        ret.append(f'rdtag="{tag}"')

    for field in record._desc.get_all_fields():
        # Omit the _version field as the Splunk adapter has no reader support for deserialising records back.
        if field == "_version":
            continue

        val = getattr(record, field)

        field = escape_field_name(field)

        if val is None:
            ret.append(f"{field}=None")
        else:
            val = to_base64(val) if isinstance(val, bytes) else to_str(val)
            val = val.replace("\\", "\\\\").replace('"', '\\"')
            ret.append(f'{field}="{val}"')

    return " ".join(ret)


def record_to_splunk_json(packer: JsonRecordPacker, record: Record, tag: str | None = None) -> dict:
    record_as_dict = packer.pack_obj(record)
    json_dict = {}

    for field, value in record_as_dict.items():
        # Omit the _version field as the Splunk adapter has no reader support for deserialising records back.
        if field == "_version":
            continue
        escaped_field = escape_field_name(field)
        json_dict[escaped_field] = value

    # Add rdump specific fields
    json_dict["rdtag"] = tag
    json_dict["rdtype"] = record._desc.name

    return json_dict


def record_to_splunk_http_api_json(packer: JsonRecordPacker, record: Record, tag: str | None = None) -> str:
    ret = {}

    indexer_fields = [
        ("host", "host"),
        ("host", "hostname"),
        ("time", "ts"),
    ]

    # When converting a record to json text for splunk, we distinguish between the 'event' (containing the data) and a
    # few other fields that are splunk-specific for indexing. We add those 'indexer_fields' to the return object first.
    for splunk_name, field_name in indexer_fields:
        if hasattr(record, field_name):
            val = getattr(record, field_name)
            if val:
                if isinstance(val, datetime):
                    # Convert datetime objects to epoch timestamp for reserved fields.
                    ret[splunk_name] = val.timestamp()
                    continue
                ret[splunk_name] = to_str(val)

    ret["event"] = record_to_splunk_json(packer, record, tag)
    return json.dumps(ret, default=packer.pack_obj)


def record_to_splunk_tcp_api_json(packer: JsonRecordPacker, record: Record, tag: str | None = None) -> str:
    record_dict = record_to_splunk_json(packer, record, tag)
    return json.dumps(record_dict, default=packer.pack_obj)


class SplunkWriter(AbstractWriter):
    sock = None
    session = None

    def __init__(
        self,
        uri: str,
        tag: str | None = None,
        token: str | None = None,
        sourcetype: str | None = None,
        ssl_verify: bool = True,
        **kwargs,
    ):
        # If the writer is initiated without a protocol, we assume we will be writing over tcp
        if "://" not in uri:
            uri = f"tcp://{uri}"

        if sourcetype is None:
            log.warning("No sourcetype provided, assuming 'records' sourcetype")
            self.sourcetype = SourceType.RECORDS
        else:
            self.sourcetype = SourceType(sourcetype)

        parsed_url = urlparse(uri)
        url_scheme = parsed_url.scheme.lower()
        self.protocol = Protocol(url_scheme)
        self.host = parsed_url.hostname
        self.port = parsed_url.port

        self.tag = tag
        self.record_buffer = []
        self._warned = False
        self.packer = None
        self.json_converter = None

        if self.protocol == Protocol.TCP:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
            self.sock.connect((self.host, self.port))
            self._send = self._send_tcp

            if self.sourcetype == SourceType.JSON:
                self.packer = JsonRecordPacker(indent=None, pack_descriptors=False)
                self.json_converter = record_to_splunk_tcp_api_json

        elif self.protocol in (Protocol.HTTP, Protocol.HTTPS):
            if not HAS_HTTPX:
                raise ImportError("The httpx library is required for sending data over HTTP(S)")

            scheme = self.protocol.value
            self.token = token
            if not self.token:
                raise ValueError("An authorization token is required for the HTTP collector")
            if not self.token.startswith("Splunk "):
                self.token = f"Splunk {self.token}"

            # Assume verify=True unless specified otherwise.
            self.verify = boolean_argument(ssl_verify)
            if not self.verify:
                log.warning("Certificate verification is disabled")

            endpoint = "event" if self.sourcetype != SourceType.RECORDS else "raw"
            port = f":{self.port}" if self.port else ""
            self.url = f"{scheme}://{self.host}{port}/services/collector/{endpoint}?auto_extract_timestamp=true"

            self.headers = {
                "Authorization": self.token,
                # A randomized value so that Splunk can loadbalance between different incoming datastreams
                "X-Splunk-Request-Channel": str(uuid.uuid4()),
            }

            self.session = httpx.Client(verify=self.verify, headers=self.headers)

            self._send = self._send_http

            if self.sourcetype == SourceType.JSON:
                self.packer = JsonRecordPacker(indent=4, pack_descriptors=False)
                self.json_converter = record_to_splunk_http_api_json

    def _cache_records_for_http(self, data: bytes | None = None, flush: bool = False) -> bytes | None:
        # It's possible to call this function without any data, purely to flush. Hence this check.
        if data:
            self.record_buffer.append(data)
        if len(self.record_buffer) < RECORD_BUFFER_LIMIT and not flush:
            # Buffer limit not exceeded yet, so we do not return a buffer yet, unless buffer is explicitly flushed.
            return None
        buf = b"".join(self.record_buffer)
        if not buf:
            return None

        # We're going to be returning a buffer for the writer to send, so we can clear the internal record buffer.
        self.record_buffer.clear()
        return buf

    def _send(self, data: bytes) -> None:
        raise RuntimeError("This method should be overridden at runtime")

    def _send_http(self, data: bytes | None = None, flush: bool = False) -> None:
        buf = self._cache_records_for_http(data, flush)
        if not buf:
            return
        response = self.session.post(self.url, data=buf)
        if response.status_code != 200:
            raise ConnectionError(f"{response.text} ({response.status_code})")

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
            rec = record_to_splunk_kv_line(record, self.tag)
        else:
            rec = self.json_converter(self.packer, record, self.tag)

        # Trail with a newline for line breaking.
        data = to_bytes(rec) + b"\n"

        self._send(data)

    def flush(self) -> None:
        if self.protocol in [Protocol.HTTP, Protocol.HTTPS]:
            self._send_http(flush=True)

    def close(self) -> None:
        # For TCP
        if self.sock:
            self.sock.close()
        self.sock = None

        if self.session:
            self.flush()
            self.session.close()
        self.session = None


class SplunkReader(AbstractReader):
    def __init__(self, path: str, selector: str | None = None, **kwargs):
        raise NotImplementedError
