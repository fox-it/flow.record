from __future__ import annotations

from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Union

from flow.record.base import FieldType
from flow.record.fieldtypes import defang

_IPNetwork = Union[IPv4Network, IPv6Network]
_IPAddress = Union[IPv4Address, IPv6Address]


class ipaddress(FieldType):
    val = None
    _type = "net.ipaddress"

    def __init__(self, addr: str | int | bytes):
        self.val = ip_address(addr)

    def __eq__(self, b: str | int | bytes | _IPAddress) -> bool:
        try:
            return self.val == ip_address(b)
        except ValueError:
            return False

    def __hash__(self) -> int:
        return hash(self.val)

    def __str__(self) -> str:
        return str(self.val)

    def __repr__(self) -> str:
        return f"{self._type}({str(self)!r})"

    def __format__(self, spec: str) -> str:
        if spec == "defang":
            return defang(str(self))
        return str.__format__(str(self), spec)

    def _pack(self) -> int:
        return int(self.val)

    @staticmethod
    def _unpack(data: int) -> ipaddress:
        return ipaddress(data)


class ipnetwork(FieldType):
    val = None
    _type = "net.ipnetwork"

    def __init__(self, addr: str | int | bytes):
        self.val = ip_network(addr)

    def __eq__(self, b: str | int | bytes | _IPNetwork) -> bool:
        try:
            return self.val == ip_network(b)
        except ValueError:
            return False

    def __hash__(self) -> int:
        return hash(self.val)

    @staticmethod
    def _is_subnet_of(a: _IPNetwork, b: _IPNetwork) -> bool:
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError("{} and {} are not of the same version".format(a, b))
            return b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address
        except AttributeError:
            raise TypeError("Unable to test subnet containment " "between {} and {}".format(a, b))

    def __contains__(self, b: str | int | bytes | _IPAddress) -> bool:
        try:
            return self._is_subnet_of(ip_network(b), self.val)
        except (ValueError, TypeError):
            return False

    def __str__(self) -> str:
        return str(self.val)

    def __repr__(self) -> str:
        return f"{self._type}({str(self)!r})"

    def _pack(self) -> str:
        return self.val.compressed

    @staticmethod
    def _unpack(data: str) -> ipnetwork:
        return ipnetwork(data)


# alias: net.IPAddress -> net.ipaddress
# alias: net.IPNetwork -> net.ipnetwork
IPAddress = ipaddress
IPNetwork = ipnetwork
