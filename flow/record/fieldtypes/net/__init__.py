from flow.record.fieldtypes import string

from .ip import IPAddress, IPNetwork, ipaddress, ipnetwork

__all__ = [
    "ipaddress",
    "ipnetwork",
    "IPAddress",
    "IPNetwork",
]


class hostname(string):
    pass


class email(string):
    pass
