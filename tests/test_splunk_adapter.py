import datetime
import json
import sys
from typing import Iterator
from unittest.mock import ANY, MagicMock, patch

import pytest

import flow.record.adapter.splunk
from flow.record import RecordDescriptor
from flow.record.adapter.splunk import (
    Protocol,
    SplunkWriter,
    splunkify_json,
    splunkify_key_value,
)
from flow.record.jsonpacker import JsonRecordPacker

BASE_FIELD_VALUES = {
    "rd__source": None,
    "rd__classification": None,
    "rd__generated": ANY,
}

JSON_PACKER = JsonRecordPacker(pack_descriptors=False)

# Reserved fields is an ordered dict so we can make assertions with a static order of reserved fields.
RESERVED_FIELDS_KEY_VALUE_SUFFIX = 'rd__source=None rd__classification=None rd__generated="'


@pytest.fixture
def mock_httpx_package(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_httpx = MagicMock()
        m.setitem(sys.modules, "httpx", mock_httpx)

        yield mock_httpx


def test_splunkify_reserved_field():
    with patch.object(
        flow.record.adapter.splunk,
        "PREFIX_WITH_RD",
        set(["foo", "_generated", "_classification", "_source"]),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")

        output_key_value = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)

        assert output_key_value.startswith(
            f'rdtype="test/record" rdtag=None rd_foo="bar" {RESERVED_FIELDS_KEY_VALUE_SUFFIX}'
        )

        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "rd_foo": "bar",
                },
                **BASE_FIELD_VALUES,
            )
        }


def test_splunkify_normal_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")

        output_key_value = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)
        assert output_key_value.startswith(
            f'rdtype="test/record" rdtag=None foo="bar" {RESERVED_FIELDS_KEY_VALUE_SUFFIX}'
        )
        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": "bar",
                },
                **BASE_FIELD_VALUES,
            )
        }


def test_splunkify_source_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "source")],
        )

        test_record = test_record_descriptor(source="file_on_target")
        test_record._source = "path_of_target"

        output_key_value = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)
        assert output_key_value.startswith(
            'rdtype="test/record" rdtag=None rd_source="file_on_target" rd__source="path_of_target"'
        )

        expected_base_field_values = BASE_FIELD_VALUES.copy()
        expected_base_field_values["rd__source"] = "path_of_target"

        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "rd_source": "file_on_target",
                    "rd__source": "path_of_target",
                    "rd__generated": ANY,
                    "rd__classification": None,
                },
            ),
        }


def test_splunkify_rdtag_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor("test/record", [])

        test_record = test_record_descriptor()

        output_key_value = splunkify_key_value(test_record, tag="bar")
        output_json = splunkify_json(JSON_PACKER, test_record, tag="bar")
        assert output_key_value.startswith(f'rdtype="test/record" rdtag="bar" {RESERVED_FIELDS_KEY_VALUE_SUFFIX}')
        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": "bar",
                    "rdtype": "test/record",
                },
                **BASE_FIELD_VALUES,
            )
        }


def test_splunkify_none_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor()

        output_key_value = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)
        assert output_key_value.startswith(
            f'rdtype="test/record" rdtag=None foo=None {RESERVED_FIELDS_KEY_VALUE_SUFFIX}'
        )
        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": None,
                },
                **BASE_FIELD_VALUES,
            )
        }


def test_splunkify_byte_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("bytes", "foo")],
        )

        test_record = test_record_descriptor(foo=b"bar")

        output_key_value = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)
        assert output_key_value.startswith(
            f'rdtype="test/record" rdtag=None foo="YmFy" {RESERVED_FIELDS_KEY_VALUE_SUFFIX}'
        )
        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": "YmFy",
                },
                **BASE_FIELD_VALUES,
            )
        }


def test_splunkify_backslash_quote_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo=b'\\"')

        output = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)
        assert output.startswith(f'rdtype="test/record" rdtag=None foo="\\\\\\"" {RESERVED_FIELDS_KEY_VALUE_SUFFIX}')
        assert json.loads(output_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": '\\"',
                },
                **BASE_FIELD_VALUES,
            )
        }


def test_splunkify_json_special_fields():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [
                ("datetime", "ts"),
                ("string", "hostname"),
                ("string", "foo"),
            ],
        )

        # Datetimes should be converted to epoch
        test_record = test_record_descriptor(ts=datetime.datetime(1970, 1, 1, 4, 0), hostname="RECYCLOPS", foo="bar")

        output = splunkify_json(JSON_PACKER, test_record)
        assert '"time": 14400.0,' in output
        assert '"host": "RECYCLOPS"' in output


def test_tcp_protocol():
    with patch("socket.socket") as mock_socket:
        tcp_writer = SplunkWriter("splunk:1337")
        assert tcp_writer.host == "splunk"
        assert tcp_writer.port == 1337
        assert tcp_writer.protocol == Protocol.TCP

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
            b'rdtype="test/record" rdtag=None foo="bar" ' + RESERVED_FIELDS_KEY_VALUE_SUFFIX.encode()
        )
        assert written_to_splunk.endswith(b'"\n')


def test_https_protocol_records_sourcetype(mock_httpx_package: MagicMock):
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
        assert sent_data.startswith(
            b'rdtype="test/record" rdtag=None foo="bar" ' + RESERVED_FIELDS_KEY_VALUE_SUFFIX.encode()
        )
        assert sent_data.endswith(b'"\n')


def test_https_protocol_json_sourcetype(mock_httpx_package: MagicMock):
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
                **BASE_FIELD_VALUES,
            )
        }
        assert json.loads(second_record_json) == {
            "event": dict(
                {
                    "rdtag": None,
                    "rdtype": "test/record",
                    "foo": "baz",
                },
                **BASE_FIELD_VALUES,
            )
        }
