from ipaddress import ip_address, ip_network
from flow.record.base import FieldType
from flow.record.fieldtypes import defang


class ipaddress(FieldType):
    val = None
    _type = "net.ipaddress"

    def __init__(self, addr):
        self.val = ip_address(addr)

    def __eq__(self, b):
        try:
            return self.val == ip_address(b)
        except ValueError:
            return False

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return "{}({!r})".format(self._type, str(self))

    def __format__(self, spec):
        if spec == "defang":
            return defang(str(self))
        return str.__format__(str(self), spec)

    def _pack(self):
        return int(self.val)

    @staticmethod
    def _unpack(data):
        return ipaddress(data)


class ipnetwork(FieldType):
    val = None
    _type = "net.ipnetwork"

    def __init__(self, addr):
        self.val = ip_network(addr)

    def __eq__(self, b):
        try:
            return self.val == ip_network(b)
        except ValueError:
            return False

    @staticmethod
    def _is_subnet_of(a, b):
        try:
            # Always false if one is v4 and the other is v6.
            if a._version != b._version:
                raise TypeError("{} and {} are not of the same version".format(a, b))
            return b.network_address <= a.network_address and b.broadcast_address >= a.broadcast_address
        except AttributeError:
            raise TypeError("Unable to test subnet containment " "between {} and {}".format(a, b))

    def __contains__(self, b):
        try:
            return self._is_subnet_of(ip_network(b), self.val)
        except (ValueError, TypeError):
            return False

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return "{}({!r})".format(self._type, str(self))

    def _pack(self):
        return self.val.compressed

    @staticmethod
    def _unpack(data):
        return ipnetwork(data)


# alias: net.IPAddress -> net.ipaddress
# alias: net.IPNetwork -> net.ipnetwork
IPAddress = ipaddress
IPNetwork = ipnetwork
