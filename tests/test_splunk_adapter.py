import datetime
import json
import sys
from typing import Iterator
from unittest.mock import ANY, MagicMock, patch

import pytest

import flow.record.adapter.splunk
from flow.record import RecordDescriptor
from flow.record.adapter.splunk import (
    SPLUNK_PROTOCOLS,
    SplunkWriter,
    splunkify_json,
    splunkify_key_value,
)
from flow.record.jsonpacker import JsonRecordPacker

BASE_FIELD_VALUES = {
    "_classification": None,
    "_generated": ANY,
    "_source": None,
    "_version": 1,
}

JSON_PACKER = JsonRecordPacker(pack_descriptors=False)


@pytest.fixture
def mock_requests_package(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_requests = MagicMock()
        m.setitem(sys.modules, "requests", mock_requests)

        yield mock_requests


def test_splunkify_reserved_field():
    with patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(["foo"]),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")

        output_key_value = splunkify_key_value(test_record)
        output_json = splunkify_json(JSON_PACKER, test_record)
        assert output_key_value == 'type="test/record" rdtag=None rd_foo="bar"'

        assert json.loads(output_json) == {"event": dict({"rdtag": None, "rd_foo": "bar"}, **BASE_FIELD_VALUES)}


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
        assert output_key_value == 'type="test/record" rdtag=None foo="bar"'
        assert json.loads(output_json) == {"event": dict({"rdtag": None, "foo": "bar"}, **BASE_FIELD_VALUES)}


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
        assert output_key_value == 'type="test/record" rdtag="bar"'
        assert json.loads(output_json) == {"event": dict({"rdtag": "bar"}, **BASE_FIELD_VALUES)}


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
        assert output_key_value == 'type="test/record" rdtag=None foo=None'
        assert json.loads(output_json) == {"event": dict({"rdtag": None, "foo": None}, **BASE_FIELD_VALUES)}


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
        assert output_key_value == 'type="test/record" rdtag=None foo="YmFy"'
        assert json.loads(output_json) == {"event": dict({"rdtag": None, "foo": "YmFy"}, **BASE_FIELD_VALUES)}


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
        assert output == 'type="test/record" rdtag=None foo="\\\\\\""'
        assert json.loads(output_json) == {"event": dict({"rdtag": None, "foo": '\\"'}, **BASE_FIELD_VALUES)}


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
        assert tcp_writer.protocol == SPLUNK_PROTOCOLS.TCP

        mock_socket.assert_called()
        mock_socket.return_value.connect.assert_called_with(("splunk", 1337))

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")
        tcp_writer.write(test_record)
        mock_socket.return_value.sendall.assert_called_with(b'type="test/record" rdtag=None foo="bar"\n')


def test_https_protocol_records_sourcetype(mock_requests_package: MagicMock):
    if "flow.record.adapter.splunk" in sys.modules:
        del sys.modules["flow.record.adapter.splunk"]

    from flow.record.adapter.splunk import (
        SPLUNK_PROTOCOLS,
        SPLUNK_SOURCETYPES,
        SplunkWriter,
    )

    with patch.object(
        flow.record.adapter.splunk,
        "HAS_REQUESTS",
        True,
    ):
        mock_requests_package.post.return_value.status_code = 200
        https_writer = SplunkWriter("https://splunk:8088", token="password123")

        assert https_writer.host == "splunk"
        assert https_writer.protocol == SPLUNK_PROTOCOLS.HTTPS
        assert https_writer.sourcetype == SPLUNK_SOURCETYPES.RECORDS
        assert https_writer.verify is True
        assert https_writer.url == "https://splunk:8088/services/collector/raw?auto_extract_timestamp=true"
        assert https_writer.headers["Authorization"] == "Splunk password123"
        assert "X-Splunk-Request-Channel" in https_writer.headers

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")
        https_writer.write(test_record)
        mock_requests_package.post.assert_not_called()

        https_writer.close()
        mock_requests_package.post.assert_called_with(
            "https://splunk:8088/services/collector/raw?auto_extract_timestamp=true",
            headers={
                "Authorization": "Splunk password123",
                "X-Splunk-Request-Channel": ANY,
            },
            verify=True,
            data=b'type="test/record" rdtag=None foo="bar"\n',
        )


def test_https_protocol_json_sourcetype(mock_requests_package: MagicMock):
    if "flow.record.adapter.splunk" in sys.modules:
        del sys.modules["flow.record.adapter.splunk"]

    from flow.record.adapter.splunk import SplunkWriter

    with patch.object(
        flow.record.adapter.splunk,
        "HAS_REQUESTS",
        True,
    ):
        mock_requests_package.post.return_value.status_code = 200

        https_writer = SplunkWriter("https://splunk:8088", token="password123", sourcetype="json")

        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")
        https_writer.write(test_record)
        mock_requests_package.post.assert_not_called()

        https_writer.close()
        mock_requests_package.post.assert_called_with(
            "https://splunk:8088/services/collector/event?auto_extract_timestamp=true",
            headers={
                "Authorization": "Splunk password123",
                "X-Splunk-Request-Channel": ANY,
            },
            verify=True,
            data=ANY,
        )

        _, kwargs = mock_requests_package.post.call_args
        called_with_data = kwargs["data"]
        assert json.loads(called_with_data) == {"event": dict({"rdtag": None, "foo": "bar"}, **BASE_FIELD_VALUES)}
