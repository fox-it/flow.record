from __future__ import annotations

import socket
import struct
import warnings
from pathlib import Path

from flow.record import FieldType


def addr_long(s: address | int | str) -> int:
    if isinstance(s, address):
        return s.val

    if isinstance(s, int):
        return s

    return struct.unpack(">I", socket.inet_aton(s))[0]


def addr_str(s: address | int | str) -> str:
    if isinstance(s, address):
        return socket.inet_ntoa(struct.pack(">I", s.val))

    if isinstance(s, int):
        return socket.inet_ntoa(struct.pack(">I", s))

    return s


def mask_to_bits(n: int) -> int:
    return bin(n).count("1")


def bits_to_mask(b: int) -> int:
    return (0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF


class subnet(FieldType):
    net = None
    mask = None
    _type = "net.ipv4.subnet"

    def __init__(self, addr: str, netmask: int | None = None):
        warnings.warn(
            "net.ipv4.subnet fieldtype is deprecated, use net.ipnetwork instead",
            DeprecationWarning,
            stacklevel=5,
        )
        if not isinstance(addr, str):
            raise TypeError(f"Subnet() argument 1 must be string, not {type(addr).__name__}")

        if netmask is None:
            ip, sep, mask = addr.partition("/")
            self.mask = bits_to_mask(int(mask)) if mask else 0xFFFFFFFF
            self.net = addr_long(ip)
        else:
            self.net = addr_long(addr)
            self.mask = bits_to_mask(netmask)

        if self.net & self.mask != self.net:
            suggest = f"{addr_str(self.net & self.mask)}/{mask_to_bits(self.mask)}"
            raise ValueError(f"Not a valid subnet {str(addr)!r}, did you mean {suggest!r} ?")

    def __contains__(self, addr: object) -> bool:
        if addr is None:
            return False

        if isinstance(addr, str):
            addr = addr_long(addr)

        if isinstance(addr, address):
            addr = addr.val

        if isinstance(addr, int):
            return addr & self.mask == self.net

        return False

    def __str__(self) -> str:
        return f"{addr_str(self.net)}/{mask_to_bits(self.mask)}"

    def __repr__(self) -> str:
        return f"{self._type}({str(self)!r})"


class SubnetList:
    subnets = None

    def __init__(self):
        self.subnets = []

    def load(self, path: str | Path) -> None:
        with Path(path).open() as fh:
            for line in fh:
                entry, desc = line.split(" ", 1)
                self.subnets.append(subnet(entry))

    def add(self, entry: str) -> None:
        self.subnets.append(subnet(entry))

    def __contains__(self, addr: object) -> bool:
        if type(addr) is str:
            addr = addr_long(addr)

        return any(addr in s for s in self.subnets)


class address(FieldType):
    val = None
    _type = "net.ipv4.address"

    def __init__(self, addr: str | int | address):
        warnings.warn(
            "net.ipv4.address fieldtype is deprecated, use net.ipaddress instead",
            DeprecationWarning,
            stacklevel=5,
        )
        self.val = addr_long(addr)

    def __eq__(self, b: object) -> bool:
        return addr_long(self) == addr_long(b)

    def __str__(self) -> str:
        return addr_str(self.val)

    def __repr__(self) -> str:
        return f"{self._type}({str(self)!r})"

    def _pack(self) -> int:
        return self.val

    @staticmethod
    def _unpack(data: int) -> address:
        return address(data)


# Backwards compatiblity
Address = address
Subnet = subnet

__all__ = ["Address", "Subnet", "SubnetList", "address", "subnet"]
