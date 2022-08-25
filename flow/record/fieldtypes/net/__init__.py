from flow.record.fieldtypes import string
from .ip import ipaddress, ipnetwork, IPAddress, IPNetwork

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
