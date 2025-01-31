from __future__ import annotations

import datetime
import json
import sys
from typing import TYPE_CHECKING
from unittest.mock import ANY, MagicMock, patch

import pytest

import flow.record.adapter.splunk
from flow.record import RecordDescriptor
from flow.record.adapter.splunk import (
    ESCAPE,
    RESERVED_FIELDS,
    Protocol,
    SourceType,
    SplunkWriter,
    escape_field_name,
    record_to_splunk_http_api_json,
    record_to_splunk_kv_line,
    record_to_splunk_tcp_api_json,
)
from flow.record.jsonpacker import JsonRecordPacker

if TYPE_CHECKING:
    from collections.abc import Iterator

# These base fields are always part of the splunk output. As they are ordered
# and ordered last in the record fields we can append them to any check of the
# splunk output values.
BASE_FIELD_JSON_VALUES = {
    f"{ESCAPE}_source": None,
    f"{ESCAPE}_classification": None,
    f"{ESCAPE}_generated": ANY,
}
BASE_FIELDS_KV_SUFFIX = f'{ESCAPE}_source=None {ESCAPE}_classification=None {ESCAPE}_generated="'

JSON_PACKER = JsonRecordPacker(pack_descriptors=False)


@pytest.fixture
def mock_httpx_package(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_httpx = MagicMock()
        m.setitem(sys.modules, "httpx", mock_httpx)

        yield mock_httpx


escaped_fields = list(
    RESERVED_FIELDS.union(
        {"_underscore_field"},
    ),
)


@pytest.mark.parametrize(
    ("field", "escaped"), [*list(zip(escaped_fields, [True] * len(escaped_fields))), ("not_escaped", False)]
)
def test_escape_field_name(field: str, escaped: bool) -> None:
    if escaped:
        assert escape_field_name(field) == f"{ESCAPE}{field}"
    else:
        assert escape_field_name(field) == field


def test_splunkify_reserved_field() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [("string", "rdtag")],
    )

    test_record = test_record_descriptor(rdtag="bar")

    output_key_value = record_to_splunk_kv_line(test_record)
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record)

    json_dict = dict(
        {
            "rdtag": None,
            "rdtype": "test/record",
            f"{ESCAPE}rdtag": "bar",
        },
        **BASE_FIELD_JSON_VALUES,
    )

    assert output_key_value.startswith(f'rdtype="test/record" rdtag=None {ESCAPE}rdtag="bar" {BASE_FIELDS_KV_SUFFIX}')
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_splunkify_normal_field() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [("string", "foo")],
    )

    test_record = test_record_descriptor(foo="bar")

    output_key_value = record_to_splunk_kv_line(test_record)
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record)

    json_dict = dict(
        {
            "rdtag": None,
            "rdtype": "test/record",
            "foo": "bar",
        },
        **BASE_FIELD_JSON_VALUES,
    )

    assert output_key_value.startswith(f'rdtype="test/record" rdtag=None foo="bar" {BASE_FIELDS_KV_SUFFIX}')
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_splunkify_source_field() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [("string", "source")],
    )

    test_record = test_record_descriptor(source="file_on_target")
    test_record._source = "path_of_target"

    output_key_value = record_to_splunk_kv_line(test_record)
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record)

    base_fields_kv_suffix = BASE_FIELDS_KV_SUFFIX.replace(
        f"{ESCAPE}_source=None",
        f'{ESCAPE}_source="{test_record._source}"',
    )

    base_field_json_values = BASE_FIELD_JSON_VALUES.copy()
    base_field_json_values[f"{ESCAPE}_source"] = test_record._source

    json_dict = dict(
        {
            "rdtag": None,
            "rdtype": "test/record",
            f"{ESCAPE}source": "file_on_target",
        },
        **base_field_json_values,
    )

    assert output_key_value.startswith(
        f'rdtype="test/record" rdtag=None {ESCAPE}source="file_on_target" {base_fields_kv_suffix}'
    )
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_splunkify_rdtag_field() -> None:
    test_record_descriptor = RecordDescriptor("test/record", [])

    test_record = test_record_descriptor()

    output_key_value = record_to_splunk_kv_line(test_record, tag="bar")
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record, tag="bar")
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record, tag="bar")

    json_dict = dict(
        {
            "rdtag": "bar",
            "rdtype": "test/record",
        },
        **BASE_FIELD_JSON_VALUES,
    )

    assert output_key_value.startswith(f'rdtype="test/record" rdtag="bar" {BASE_FIELDS_KV_SUFFIX}')
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_splunkify_none_field() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [("string", "foo")],
    )

    test_record = test_record_descriptor()

    output_key_value = record_to_splunk_kv_line(test_record)
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record)

    json_dict = dict(
        {
            "rdtag": None,
            "rdtype": "test/record",
            "foo": None,
        },
        **BASE_FIELD_JSON_VALUES,
    )

    assert output_key_value.startswith(f'rdtype="test/record" rdtag=None foo=None {BASE_FIELDS_KV_SUFFIX}')
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_splunkify_byte_field() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [("bytes", "foo")],
    )

    test_record = test_record_descriptor(foo=b"bar")

    output_key_value = record_to_splunk_kv_line(test_record)
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record)

    json_dict = dict(
        {
            "rdtag": None,
            "rdtype": "test/record",
            "foo": "YmFy",
        },
        **BASE_FIELD_JSON_VALUES,
    )

    assert output_key_value.startswith(f'rdtype="test/record" rdtag=None foo="YmFy" {BASE_FIELDS_KV_SUFFIX}')
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_splunkify_backslash_quote_field() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [("string", "foo")],
    )

    test_record = test_record_descriptor(foo=b'\\"')

    output = record_to_splunk_kv_line(test_record)
    output_http_json = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    output_tcp_json = record_to_splunk_tcp_api_json(JSON_PACKER, test_record)

    json_dict = dict(
        {
            "rdtag": None,
            "rdtype": "test/record",
            "foo": '\\"',
        },
        **BASE_FIELD_JSON_VALUES,
    )

    assert output.startswith(f'rdtype="test/record" rdtag=None foo="\\\\\\"" {BASE_FIELDS_KV_SUFFIX}')
    assert json.loads(output_http_json) == {"event": json_dict}
    assert json.loads(output_tcp_json) == json_dict


def test_record_to_splunk_http_api_json_special_fields() -> None:
    test_record_descriptor = RecordDescriptor(
        "test/record",
        [
            ("datetime", "ts"),
            ("string", "hostname"),
            ("string", "foo"),
        ],
    )

    # Datetimes should be converted to epoch
    test_record = test_record_descriptor(ts=datetime.datetime(1970, 1, 1, 4, 0), hostname="RECYCLOPS", foo="bar")  # noqa: DTZ001

    output = record_to_splunk_http_api_json(JSON_PACKER, test_record)
    assert '"time": 14400.0,' in output
    assert '"host": "RECYCLOPS"' in output


def test_tcp_protocol_records_sourcetype() -> None:
    with patch("socket.socket") as mock_socket:
        tcp_writer = SplunkWriter("splunk:1337")
        assert tcp_writer.host == "splunk"
        assert tcp_writer.port == 1337
        assert tcp_writer.protocol == Protocol.TCP
        assert tcp_writer.sourcetype == SourceType.RECORDS

        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(("splunk", 1337))

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")
        tcp_writer.write(test_record)

        args, _ = mock_socket.return_value.sendall.call_args
        written_to_splunk = args[0]

        assert written_to_splunk.startswith(
            b'rdtype="test/record" rdtag=None foo="bar" ' + BASE_FIELDS_KV_SUFFIX.encode()
        )
        assert written_to_splunk.endswith(b'"\n')


def test_tcp_protocol_json_sourcetype() -> None:
    with patch("socket.socket") as mock_socket:
        tcp_writer = SplunkWriter("splunk:1337", sourcetype="json")
        assert tcp_writer.host == "splunk"
        assert tcp_writer.port == 1337
        assert tcp_writer.protocol == Protocol.TCP
        assert tcp_writer.sourcetype == SourceType.JSON

        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(("splunk", 1337))

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")
        tcp_writer.write(test_record)

        args, _ = mock_socket.return_value.sendall.call_args
        written_to_splunk = args[0]

        json_dict = dict(
            {
                "rdtag": None,
                "rdtype": "test/record",
                "foo": "bar",
            },
            **BASE_FIELD_JSON_VALUES,
        )

        assert json.loads(written_to_splunk) == json_dict
        assert written_to_splunk.endswith(b"\n")


def test_https_protocol_records_sourcetype(mock_httpx_package: MagicMock) -> None:
    if "flow.record.adapter.splunk" in sys.modules:
        del sys.modules["flow.record.adapter.splunk"]

    from flow.record.adapter.splunk import Protocol, SourceType, SplunkWriter

    with patch.object(
        flow.record.adapter.splunk,
        "HAS_HTTPX",
        True,
    ):
        mock_httpx_package.Client.return_value.post.return_value.status_code = 200
        https_writer = SplunkWriter("https://splunk:8088", token="password123")

        assert https_writer.host == "splunk"
        assert https_writer.protocol == Protocol.HTTPS
        assert https_writer.sourcetype == SourceType.RECORDS
        assert https_writer.verify is True
        assert https_writer.url == "https://splunk:8088/services/collector/raw?auto_extract_timestamp=true"

        _, kwargs = mock_httpx_package.Client.call_args
        assert kwargs["verify"] is True

        given_headers = kwargs["headers"]
        assert given_headers["Authorization"] == "Splunk password123"
        assert "X-Splunk-Request-Channel" in given_headers

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")
        https_writer.write(test_record)

        mock_httpx_package.Client.return_value.post.assert_not_called()

        https_writer.close()
        mock_httpx_package.Client.return_value.post.assert_called_with(
            "https://splunk:8088/services/collector/raw?auto_extract_timestamp=true",
            data=ANY,
        )
        _, kwargs = mock_httpx_package.Client.return_value.post.call_args
        sent_data = kwargs["data"]
        assert sent_data.startswith(b'rdtype="test/record" rdtag=None foo="bar" ' + BASE_FIELDS_KV_SUFFIX.encode())
        assert sent_data.endswith(b'"\n')


def test_https_protocol_json_sourcetype(mock_httpx_package: MagicMock) -> None:
    if "flow.record.adapter.splunk" in sys.modules:
        del sys.modules["flow.record.adapter.splunk"]

    from flow.record.adapter.splunk import SplunkWriter

    with patch.object(
        flow.record.adapter.splunk,
        "HAS_HTTPX",
        True,
    ):
        mock_httpx_package.Client.return_value.post.return_value.status_code = 200

        https_writer = SplunkWriter("https://splunk:8088", token="password123", sourcetype="json")

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        https_writer.write(test_record_descriptor(foo="bar"))
        https_writer.write(test_record_descriptor(foo="baz"))
        mock_httpx_package.Client.return_value.post.assert_not_called()

        https_writer.close()
        mock_httpx_package.Client.return_value.post.assert_called_with(
            "https://splunk:8088/services/collector/event?auto_extract_timestamp=true",
            data=ANY,
        )

        _, kwargs = mock_httpx_package.Client.return_value.post.call_args
        sent_data = kwargs["data"]
        first_record_json, _, second_record_json = sent_data.partition(b"\n")
        assert json.loads(first_record_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": "bar",
                },
                **BASE_FIELD_JSON_VALUES,
            )
        }
        assert json.loads(second_record_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": "baz",
                },
                **BASE_FIELD_JSON_VALUES,
            )
        }
