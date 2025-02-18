from __future__ import annotations

WHITELIST = [
    "boolean",
    "command",
    "dynamic",
    "datetime",
    "filesize",
    "uint16",
    "uint32",
    "float",
    "string",
    "stringlist",
    "dictlist",
    "unix_file_mode",
    "varint",
    "wstring",
    "net.ipv4.Address",
    "net.ipv4.Subnet",
    "net.tcp.Port",
    "net.udp.Port",
    "uri",
    "digest",
    "bytes",
    "record",
    "net.ipaddress",
    "net.ipinterface",
    "net.ipnetwork",
    "net.IPAddress",
    "net.IPNetwork",
    "path",
]


WHITELIST_TREE = {}
for field in WHITELIST:
    parent = None
    obj = WHITELIST_TREE
    for part in field.split("."):
        if part not in obj:
            obj[part] = {}
        parent = obj
        obj = obj[part]

    parent[part] = True
