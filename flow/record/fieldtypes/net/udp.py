from __future__ import annotations

from flow.record.fieldtypes import uint16


class port(uint16):
    pass


# Backwards compatiblity
Port = port
