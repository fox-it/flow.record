from __future__ import unicode_literals
import random
import ipaddress

import pytest

from flow.record import RecordDescriptor, RecordWriter, RecordReader
from flow.record import RecordPacker
from flow.record.fieldtypes import net
from flow.record.selector import Selector, CompiledSelector


def test_field_ipaddress():
    a = net.IPAddress("192.168.1.1")
    assert a == "192.168.1.1"

    with pytest.raises(ValueError) as excinfo:
        net.IPAddress("a.a.a.a")
    excinfo.match(".* does not appear to be an IPv4 or IPv6 address")


def test_field_ipnetwork():
    a = net.IPNetwork("192.168.1.0/24")
    assert a == "192.168.1.0/24"

    # Host bits set
    with pytest.raises(ValueError) as excinfo:
        net.IPNetwork("192.168.1.10/24")
    excinfo.match(".* has host bits set")


def test_record_ipaddress():
    TestRecord = RecordDescriptor(
        "test/ipaddress",
        [
            ("net.ipaddress", "ip"),
        ],
    )

    r = TestRecord("127.0.0.1")
    assert r.ip == "127.0.0.1"
    assert r.ip != "lala.1234.bad.ip"
    assert isinstance(r.ip, net.ipaddress)
    assert repr(r.ip) == "net.ipaddress('127.0.0.1')"

    # ipv4
    assert TestRecord("1.1.1.1").ip == "1.1.1.1"
    assert TestRecord("0.0.0.0").ip == "0.0.0.0"
    assert TestRecord("192.168.0.1").ip == "192.168.0.1"
    assert TestRecord("255.255.255.255").ip == "255.255.255.255"

    # ipv6
    assert TestRecord("::1").ip == "::1"
    assert TestRecord("2001:4860:4860::8888").ip == "2001:4860:4860::8888"
    assert TestRecord("2001:4860:4860::4444").ip == "2001:4860:4860::4444"

    # instantiate from different types
    assert TestRecord(1).ip == "0.0.0.1"
    assert TestRecord(0x7F0000FF).ip == "127.0.0.255"
    assert TestRecord(b"\x7f\xff\xff\xff").ip == "127.255.255.255"
    assert TestRecord("127.0.0.1").ip == "127.0.0.1"

    # invalid ip addresses
    for invalid in ["1.1.1.256", "192.168.0.1/24", "a.b.c.d", ":::::1"]:
        with pytest.raises(Exception) as excinfo:
            TestRecord(invalid)
        excinfo.match(r".*does not appear to be an IPv4 or IPv6 address*")

    r = TestRecord()
    assert r.ip is None


def test_record_ipnetwork():
    TestRecord = RecordDescriptor(
        "test/ipnetwork",
        [
            ("net.ipnetwork", "subnet"),
        ],
    )

    # ipv4
    r = TestRecord("192.168.0.0/24")
    assert r.subnet == "192.168.0.0/24"
    assert r.subnet != "bad.sub/net"
    assert "bad.ip" not in r.subnet
    assert "192.168.0.1" in r.subnet
    assert "192.168.0.2/32" in r.subnet
    assert "192.168.0.255" in r.subnet
    assert "192.168.0.128/30" in r.subnet
    assert "192.168.1.1" not in r.subnet
    assert isinstance(r.subnet, net.ipnetwork)
    assert repr(r.subnet) == "net.ipnetwork('192.168.0.0/24')"

    r = TestRecord("192.168.1.1/32")
    assert r.subnet == "192.168.1.1"
    assert r.subnet == "192.168.1.1/32"
    assert "192.168.1.1" in r.subnet
    assert "192.168.1.1/32" in r.subnet

    # ipv6 - https://en.wikipedia.org/wiki/IPv6_address
    r = TestRecord("::1")
    assert r.subnet == "::1"
    assert r.subnet == "::1/128"

    r = TestRecord("::/0")
    assert "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" in r.subnet
    assert "::" in r.subnet
    assert "::1" in r.subnet

    r = TestRecord("64:ff9b::/96")
    assert "64:ff9b::0.0.0.0" in r.subnet
    assert "64:ff9b::255.255.255.255" in r.subnet


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_ipaddress(PSelector):
    TestRecord = RecordDescriptor(
        "test/ipaddress",
        [
            ("string", "description"),
            ("net.ipaddress", "ip"),
        ],
    )

    records = [
        TestRecord("Google DNS IPv4", "8.8.8.8"),
        TestRecord("Google DNS IPv4", "8.8.4.4"),
        TestRecord("Google DNS IPv6", "2001:4860:4860::8888"),
        TestRecord("Google DNS IPv6", "2001:4860:4860::4444"),
    ]

    recs = [r for r in records if r in PSelector("r.ip in net.ipnetwork('8.8.0.0/16')")]
    assert len(recs) == 2

    recs = [r for r in records if r in PSelector("r.ip == '8.8.8.8'")]
    assert len(recs) == 1

    recs = [r for r in records if r in PSelector("r.ip in net.ipnetwork('2001:4860:4860::/48')")]
    assert len(recs) == 2

    record = TestRecord("Optional", None)
    assert record not in PSelector("r.ip == '1.1.1.1'")
    assert record in PSelector("r.ip == None")
    assert record in PSelector("not r.ip")


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_ipnetwork(PSelector):
    TestRecord = RecordDescriptor(
        "test/ipnetwork",
        [
            ("string", "description"),
            ("net.ipnetwork", "subnet"),
        ],
    )

    records = [
        # ipv4
        TestRecord("RFC1918", "10.0.0.0/8"),
        TestRecord("RFC1918", "172.16.0.0/12"),
        TestRecord("RFC1918", "192.168.0.0/16"),
        # ipv6
        TestRecord("Private network", "fc00::/7"),
        TestRecord("Link local", "fe80::/10"),
        TestRecord("Facebook IPv6 range", "2a03:2880::/32"),
    ]
    recs = [r for r in records if r in PSelector("'fe80::1ff:fe23:4567:890a' in r.subnet")]
    assert len(recs) == 1

    recs = [r for r in records if r in PSelector("'2a03:2880:f003:c07:face:b00c::2' in r.subnet")]
    assert len(recs) == 1

    recs = [r for r in records if r in PSelector("'192.168.1.0/24' in r.subnet")]
    assert len(recs) == 1
    assert recs[0].subnet == "192.168.0.0/16"

    recs = [r for r in records if r in PSelector("'192.168.1.141' in r.subnet")]
    assert len(recs) == 1
    assert recs[0].subnet == "192.168.0.0/16"

    record = TestRecord("Google", "8.0.0.0/8")
    assert record in PSelector("'8.8.4.4' in r.subnet")
    assert record in PSelector("'8.8.8.8/32' in r.subnet")
    assert record in PSelector("'8.8.0.0/16' in r.subnet")
    assert record in PSelector("'8.8.4.0/24' in r.subnet")
    assert record in PSelector("'8.8.8.0/24' in r.subnet")

    record = TestRecord("Optional", None)
    assert record not in PSelector("r.subnet and '1.1.1.1' in r.subnet")
    assert record in PSelector("r.subnet == None")
    assert record in PSelector("not r.subnet")


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_ipaddress_in_ipnetwork(PSelector):
    TestRecord = RecordDescriptor(
        "test/scandata",
        [
            ("net.ipaddress", "ip"),
            ("uint16", "port"),
            ("string", "description"),
        ],
    )

    records = [
        TestRecord("8.8.8.8", 53, "google"),
        TestRecord("1.1.1.1", 53, "cloudflare"),
        TestRecord("2620:fe::9", 53, "quad9"),
        TestRecord(None, None, "empty"),
    ]

    for record in records:
        if record in PSelector('r.ip in net.ipnetwork("8.8.0.0/16")'):
            assert record.ip == "8.8.8.8"

    for record in records:
        if record in PSelector('r.ip in net.ipnetwork("1.1.1.1/32")'):
            assert record.ip == "1.1.1.1"

    for record in records:
        if record in PSelector('r.ip in net.ipnetwork("2620:FE::/48")'):
            assert record.description == "quad9"
            assert record.ip == "2620:00fe:0:0:0:0:0:0009"


def test_pack_ipaddress():
    packer = RecordPacker()

    TestRecord = RecordDescriptor(
        "test/ipaddress",
        [
            ("net.ipaddress", "ip"),
        ],
    )

    # ipv4
    record_in = TestRecord("10.22.99.255")
    data = packer.pack(record_in)
    record_out = packer.unpack(data)
    assert record_in == record_out

    # ipv6
    record_in = TestRecord("2001:4860:4860::8888")
    data = packer.pack(record_in)
    record_out = packer.unpack(data)
    assert record_in == record_out


@pytest.mark.parametrize("ip_bits", [32, 128])
def test_record_writer_reader_ipaddress(tmpdir, ip_bits):
    TestRecord = RecordDescriptor(
        "test/ipaddress",
        [
            ("net.ipaddress", "ip"),
        ],
    )

    ips = [ipaddress.ip_address(random.getrandbits(ip_bits)) for _ in range(20)]
    with RecordWriter(tmpdir.join("ip.records")) as writer:
        for ip in ips:
            writer.write(TestRecord(ip))

    with RecordReader(tmpdir.join("ip.records")) as reader:
        for i, r in enumerate(reader):
            assert r.ip == ips[i]


def test_pack_ipnetwork():
    packer = RecordPacker()

    TestRecord = RecordDescriptor(
        "test/ipnetwork",
        [
            ("net.ipnetwork", "subnet"),
        ],
    )

    record_in = TestRecord("172.16.0.0/16")
    data = packer.pack(record_in)
    record_out = packer.unpack(data)
    assert record_in == record_out

    # subnet should be encoded as string
    assert b"172.16.0.0/16" in data
