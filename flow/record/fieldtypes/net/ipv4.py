import struct
import socket

from flow.record import FieldType
from flow.record.utils import to_native_str


def addr_long(s):
    if isinstance(s, Address):
        return s.val

    if isinstance(s, int):
        return s

    return struct.unpack(">I", socket.inet_aton(s))[0]


def addr_str(s):
    if isinstance(s, Address):
        return socket.inet_ntoa(struct.pack(">I", s.val))

    if isinstance(s, int):
        return socket.inet_ntoa(struct.pack(">I", s))

    return s


def mask_to_bits(n):
    return bin(n).count("1")


def bits_to_mask(b):
    return (0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF


class subnet(FieldType):
    net = None
    mask = None
    _type = "net.ipv4.subnet"

    def __init__(self, addr, netmask=None):
        if isinstance(addr, type("")):
            addr = to_native_str(addr)

        if not isinstance(addr, str):
            raise TypeError("Subnet() argument 1 must be string, not {}".format(type(addr).__name__))

        if netmask is None:
            ip, sep, mask = addr.partition("/")
            self.mask = bits_to_mask(int(mask)) if mask else 0xFFFFFFFF
            self.net = addr_long(ip)
        else:
            self.net = addr_long(addr)
            self.mask = bits_to_mask(netmask)

        if self.net & self.mask != self.net:
            suggest = "{}/{}".format(addr_str(self.net & self.mask), mask_to_bits(self.mask))
            raise ValueError("Not a valid subnet {!r}, did you mean {!r} ?".format(str(addr), suggest))

    def __contains__(self, addr):
        if addr is None:
            return False

        if isinstance(addr, type("")):
            addr = to_native_str(addr)

        if isinstance(addr, str):
            addr = addr_long(addr)

        if isinstance(addr, Address):
            addr = addr.val

        if isinstance(addr, int):
            return addr & self.mask == self.net

        return False

    def __str__(self):
        return "{0}/{1}".format(addr_str(self.net), mask_to_bits(self.mask))

    def __repr__(self):
        return "{}({!r})".format(self._type, str(self))


class SubnetList:
    subnets = None

    def __init__(self):
        self.subnets = []

    def load(self, path):
        f = open(path, "rb")
        for line in f:
            entry, desc = line.split(" ", 1)
            self.subnets.append(Subnet(entry))

        f.close()

    def add(self, subnet):
        self.subnets.append(Subnet(subnet))

    def __contains__(self, addr):
        if type(addr) is str:
            addr = addr_long(addr)

        return any(addr in s for s in self.subnets)


class address(FieldType):
    val = None
    _type = "net.ipv4.address"

    def __init__(self, addr):
        self.val = addr_long(addr)

    def __eq__(self, b):
        return addr_long(self) == addr_long(b)

    def __str__(self):
        return addr_str(self.val)

    def __repr__(self):
        return "{}({!r})".format(self._type, str(self))

    def _pack(self):
        return self.val

    @staticmethod
    def _unpack(data):
        return address(data)


# Backwards compatiblity
Address = address
Subnet = subnet

__all__ = ["address", "subnet", "Address", "Subnet", "SubnetList"]
