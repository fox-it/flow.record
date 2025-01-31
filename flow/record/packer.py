from __future__ import annotations

import functools
import warnings
from datetime import datetime, timezone
from typing import Any

import msgpack

from flow.record import fieldtypes
from flow.record.base import (
    RECORD_VERSION,
    RESERVED_FIELDS,
    FieldType,
    GroupedRecord,
    Record,
    RecordDescriptor,
)
from flow.record.exceptions import RecordDescriptorNotFound
from flow.record.utils import EventHandler, to_str

# Override defaults for msgpack packb/unpackb
packb = functools.partial(msgpack.packb, use_bin_type=True, unicode_errors="surrogateescape")
unpackb = functools.partial(msgpack.unpackb, raw=False, unicode_errors="surrogateescape")

RECORD_PACK_EXT_TYPE = 0xE

RECORD_PACK_TYPE_RECORD = 0x1
RECORD_PACK_TYPE_DESCRIPTOR = 0x2
RECORD_PACK_TYPE_FIELDTYPE = 0x3
RECORD_PACK_TYPE_DATETIME = 0x10
RECORD_PACK_TYPE_VARINT = 0x11
RECORD_PACK_TYPE_GROUPEDRECORD = 0x12

UTC = timezone.utc


def identifier_to_str(identifier: tuple[str, int] | str) -> tuple[str, int] | str:
    if isinstance(identifier, tuple) and len(identifier) == 2:
        return (to_str(identifier[0]), identifier[1])

    return to_str(identifier)


class RecordPacker:
    EXT_TYPE = RECORD_PACK_EXT_TYPE
    TYPES = (FieldType, Record, RecordDescriptor)

    def __init__(self):
        self.descriptors = {}
        self.on_descriptor = EventHandler()

    def register(self, desc: RecordDescriptor, notify: bool = False) -> None:
        if not isinstance(desc, RecordDescriptor):
            raise TypeError("Expected Record Descriptor")

        # versioned record descriptor
        self.descriptors[desc.identifier] = desc

        # for older non versioned records
        self.descriptors[desc.name] = desc

        if notify and self.on_descriptor:
            self.on_descriptor(desc)

    def pack_obj(self, obj: Any, unversioned: bool = False) -> msgpack.ExtType:
        packed = None

        if isinstance(obj, datetime):
            if obj.tzinfo is None or obj.tzinfo == UTC:
                packed = (RECORD_PACK_TYPE_DATETIME, (*obj.timetuple()[:6], obj.microsecond))
            else:
                packed = (RECORD_PACK_TYPE_DATETIME, (obj.isoformat(),))

        elif isinstance(obj, int):
            neg = obj < 0
            v = abs(obj)
            packed = RECORD_PACK_TYPE_VARINT, (neg, v.to_bytes((v.bit_length() + 7) // 8, "big"))

        elif isinstance(obj, GroupedRecord):
            for desc in obj.descriptors:
                if desc.identifier not in self.descriptors:
                    self.register(desc, True)

            packed = RECORD_PACK_TYPE_GROUPEDRECORD, obj._pack()

        elif isinstance(obj, Record):
            if obj._desc.identifier not in self.descriptors:
                self.register(obj._desc, True)

            data = obj._pack(unversioned=unversioned)
            packed = RECORD_PACK_TYPE_RECORD, data

        elif isinstance(obj, RecordDescriptor):
            packed = RECORD_PACK_TYPE_DESCRIPTOR, obj._pack()

        if not packed:
            raise TypeError("Unpackable type " + str(type(obj)))

        return msgpack.ExtType(RECORD_PACK_EXT_TYPE, self.pack(packed))

    def pack(self, obj: Any) -> bytes:
        return packb(obj, default=self.pack_obj)

    def unpack_obj(self, t: int, data: bytes) -> Any:
        if t != RECORD_PACK_EXT_TYPE:
            raise TypeError("Unknown ExtType")

        subtype, value = self.unpack(data)

        if subtype == RECORD_PACK_TYPE_DATETIME:
            return fieldtypes.datetime(*value)

        if subtype == RECORD_PACK_TYPE_VARINT:
            neg, h = value
            v = int.from_bytes(h, "big")
            if neg:
                v = -v

            return v

        if subtype == RECORD_PACK_TYPE_RECORD:
            identifier, values = value
            identifier = identifier_to_str(identifier)

            desc = self.descriptors.get(identifier)
            if not desc:
                raise RecordDescriptorNotFound(f"No RecordDescriptor found for: {identifier}")

            # Compatibility for older records
            # We check the actual amount of values against the expected amount of values
            # The values received include reserved fields, so we have to add them to the
            # fields already declared in the descriptor.
            # The descriptor should be received from the same stream, so any inconsistency
            # in field count should be from reserved fields.
            version = values[-1]
            expected_len = len(desc.fields) + len(RESERVED_FIELDS)

            # Perform some basic checking on record version, if any, and issue a warning if needed.
            if not isinstance(version, int) or version < 1 or version > 255:
                warnings.warn(
                    (
                        f"Got old style record with no version information (expected {RECORD_VERSION:d}). "
                        "Compatibility is not guaranteed."
                    ),
                    RuntimeWarning,
                    stacklevel=2,
                )
            elif version != RECORD_VERSION:
                warnings.warn(
                    f"Got other version record (expected {RECORD_VERSION:d}, got {version:d}). "
                    "Compatibility is not guaranteed.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                # Optionally add compatibility code here later

            # If the actual amount of fields is less, there's nothing we can really do.
            # If the actual amount of fields is more, we strip additional fields but
            # maintain the version field
            # This implies that any record that has _more_ reserved fields always
            # has a version field.
            if len(values) > expected_len:
                # Likely newer style record. Strip extra fields but maintain version field
                values = values[: expected_len - 1]
                values += (version,)

            return desc.recordType._unpack(*values)

        if subtype == RECORD_PACK_TYPE_GROUPEDRECORD:
            name, packed_records = value
            records = []
            for value in packed_records:
                identifier, values = value
                identifier = identifier_to_str(identifier)
                desc = self.descriptors[identifier]
                records.append(desc.recordType._unpack(*values))
            return GroupedRecord(name, records)

        if subtype == RECORD_PACK_TYPE_DESCRIPTOR:
            name, fields = value
            name = to_str(name)
            return RecordDescriptor._unpack(name, fields)

        raise TypeError(f"Unknown subtype: {subtype:x}")

    def unpack(self, d: bytes) -> Any:
        return unpackb(d, ext_hook=self.unpack_obj, use_list=False)
