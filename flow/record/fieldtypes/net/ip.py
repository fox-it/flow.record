from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Union

from flow.record.base import FieldType
from flow.record.fieldtypes import defang


class ipaddress(FieldType):
    val = None
    _type = "net.ipaddress"

    def __init__(self, addr: Union[str, int]):
        self.val = ip_address(addr)

    def __eq__(self, b: Union[str, int]) -> bool:
        try:
            return self.val == ip_address(b)
        except ValueError:
            return False

    def __hash__(self) -> int:
        return hash(self.val)

    def __str__(self) -> str:
        return str(self.val)

    def __repr__(self) -> str:
        return "{}({!r})".format(self._type, str(self))

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

    def __init__(self, addr: Union[str, int]):
        self.val = ip_network(addr)

    def __eq__(self, b: Union[str, int]) -> bool:
        try:
            return self.val == ip_network(b)
        except ValueError:
            return False

    def __hash__(self) -> int:
        return hash(self.val)

    @staticmethod
    def _is_subnet_of(a: ip_network, b: ip_network) -> bool:
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError("{} and {} are not of the same version".format(a, b))
            return b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address
        except AttributeError:
            raise TypeError("Unable to test subnet containment " "between {} and {}".format(a, b))

    def __contains__(self, b: Union[str, int, ip_address]) -> bool:
        try:
            return self._is_subnet_of(ip_network(b), self.val)
        except (ValueError, TypeError):
            return False

    def __str__(self) -> str:
        return str(self.val)

    def __repr__(self) -> str:
        return "{}({!r})".format(self._type, str(self))

    def _pack(self) -> str:
        return self.val.compressed

    @staticmethod
    def _unpack(data: str) -> ipnetwork:
        return ipnetwork(data)


# alias: net.IPAddress -> net.ipaddress
# alias: net.IPNetwork -> net.ipnetwork
IPAddress = ipaddress
IPNetwork = ipnetwork
