from __future__ import annotations

import pytest

from flow.record import RecordDescriptor
from flow.record.base import parse_def


def test_deprecate_ipv4_address() -> None:
    TestRecord = RecordDescriptor(
        "test/net/ipv4/Address",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )

    with pytest.warns(DeprecationWarning, match="net.ipv4.address fieldtype is deprecated, use net.ipaddress instead"):
        TestRecord("127.0.0.1")


def test_deprecate_ipv4_subnet() -> None:
    TestRecord = RecordDescriptor(
        "test/net/ipv4/Subnet",
        [
            ("net.ipv4.Subnet", "network"),
        ],
    )

    with pytest.warns(DeprecationWarning, match="net.ipv4.subnet fieldtype is deprecated, use net.ipnetwork instead"):
        TestRecord("192.168.0.0/24")


def test_deprecate_parse_def() -> None:
    with pytest.deprecated_call():
        parse_def("test/record")


def test_deprecate_recorddescriptor_init() -> None:
    # Test deprecated RecordDescriptor init with string def
    with pytest.deprecated_call():
        TestRecord = RecordDescriptor("test/record", None)
    assert TestRecord.name == "test/record"

    # Test deprecated RecordDescriptor init with string def and some fields
    with pytest.deprecated_call():
        TestRecord = RecordDescriptor(
            """test/record
            string foo
            """
        )
    assert TestRecord(foo="bar").foo == "bar"

    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "foo"),
        ],
    )
    # Test deprecated RecordDescriptor init with another RecordDescriptor
    with pytest.deprecated_call():
        TestRecord2 = RecordDescriptor("test/init_other_descriptor", TestRecord)
    assert TestRecord2(foo="bar").foo == "bar"
