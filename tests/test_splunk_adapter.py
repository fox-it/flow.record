from unittest import mock

from flow.record import RecordDescriptor
import flow.record.adapter.splunk
from flow.record.adapter.splunk import splunkify


def test_splunkify_reserved_field():

    with mock.patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(["foo"]),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")

        output = splunkify(test_record)
        assert output == 'type="test/record" rdtag=None rd_foo="bar"'


def test_splunkify_normal_field():

    with mock.patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo="bar")

        output = splunkify(test_record)
        assert output == 'type="test/record" rdtag=None foo="bar"'


def test_splunkify_rdtag_field():

    with mock.patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
        )

        test_record = test_record_descriptor()

        output = splunkify(test_record, tag="bar")
        assert output == 'type="test/record" rdtag="bar"'


def test_splunkify_none_field():

    with mock.patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor()

        output = splunkify(test_record)
        assert output == 'type="test/record" rdtag=None foo=None'


def test_splunkify_byte_field():

    with mock.patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("bytes", "foo")],
        )

        test_record = test_record_descriptor(foo=b"bar")

        output = splunkify(test_record)
        assert output == 'type="test/record" rdtag=None foo="YmFy"'


def test_splunkify_backslash_quote_field():

    with mock.patch.object(
        flow.record.adapter.splunk,
        "RESERVED_SPLUNK_FIELDS",
        set(),
    ):
        test_record_descriptor = RecordDescriptor(
            "test/record",
            [("string", "foo")],
        )

        test_record = test_record_descriptor(foo=b'\\"')

        output = splunkify(test_record)
        assert output == 'type="test/record" rdtag=None foo="\\\\\\""'
