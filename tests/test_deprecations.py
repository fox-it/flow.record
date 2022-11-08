import pytest

from flow.record import RecordDescriptor


def test_deprecate_ipv4_address():
    TestRecord = RecordDescriptor(
        "test/net/ipv4/Address",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )

    with pytest.warns(DeprecationWarning, match="net.ipv4.address fieldtype is deprecated, use net.ipaddress instead"):
        TestRecord("127.0.0.1")


def test_deprecate_ipv4_subnet():
    TestRecord = RecordDescriptor(
        "test/net/ipv4/Subnet",
        [
            ("net.ipv4.Subnet", "network"),
        ],
    )

    with pytest.warns(DeprecationWarning, match="net.ipv4.subnet fieldtype is deprecated, use net.ipnetwork instead"):
        TestRecord("192.168.0.0/24")
