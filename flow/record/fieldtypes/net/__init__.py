from __future__ import annotations

from flow.record.fieldtypes import string
from flow.record.fieldtypes.net.ip import (
    IPAddress,
    IPInterface,
    IPNetwork,
    ipaddress,
    ipinterface,
    ipnetwork,
)

__all__ = [
    "IPAddress",
    "IPInterface",
    "IPNetwork",
    "ipaddress",
    "ipinterface",
    "ipnetwork",
]


class hostname(string):
    pass


class email(string):
    pass
