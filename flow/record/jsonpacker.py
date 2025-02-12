from __future__ import annotations

import base64
import json
import logging
from datetime import datetime
from typing import Any

from flow.record import fieldtypes
from flow.record.base import Record, RecordDescriptor
from flow.record.exceptions import RecordDescriptorNotFound
from flow.record.utils import EventHandler

log = logging.getLogger(__package__)


class JsonRecordPacker:
    def __init__(self, indent: int | None = None, pack_descriptors: bool = True):
        self.descriptors = {}
        self.on_descriptor = EventHandler()
        self.pack_descriptors = pack_descriptors
        self.indent = indent

    def register(self, desc: RecordDescriptor, notify: bool = False) -> None:
        if not isinstance(desc, RecordDescriptor):
            raise TypeError("Expected Record Descriptor")

        # Descriptor already known
        if desc.identifier in self.descriptors:
            return

        # versioned record descriptor
        self.descriptors[desc.identifier] = desc

        # for older non versioned records
        self.descriptors[desc.name] = desc

        if notify and self.on_descriptor:
            log.debug("JsonRecordPacker::on_descriptor %s", desc)
            self.on_descriptor(desc)

    def pack_obj(self, obj: Any) -> dict | str:
        if isinstance(obj, Record):
            if obj._desc.identifier not in self.descriptors:
                self.register(obj._desc, True)
            serial = obj._asdict()

            if self.pack_descriptors:
                serial["_type"] = "record"
                serial["_recorddescriptor"] = obj._desc.identifier

            for field_type, field_name in obj._desc.get_field_tuples():
                # Boolean field types should be cast to a bool instead of staying ints
                if field_type == "boolean" and isinstance(serial[field_name], int):
                    serial[field_name] = bool(serial[field_name])

            return serial
        if isinstance(obj, RecordDescriptor):
            return {
                "_type": "recorddescriptor",
                "_data": obj._pack(),
            }
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, fieldtypes.digest):
            return {
                "md5": obj.md5,
                "sha1": obj.sha1,
                "sha256": obj.sha256,
            }
        if isinstance(obj, (fieldtypes.net.ipaddress, fieldtypes.net.ipnetwork, fieldtypes.net.ipinterface)):
            return str(obj)
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        if isinstance(obj, fieldtypes.path):
            return str(obj)
        if isinstance(obj, fieldtypes.command):
            return {
                "executable": obj.executable,
                "args": obj.args,
            }

        raise TypeError(f"Unpackable type {type(obj)}")

    def unpack_obj(self, obj: Any) -> RecordDescriptor | Record | Any:
        if isinstance(obj, dict):
            _type = obj.get("_type", None)
            if _type == "record":
                record_descriptor_identifier = obj["_recorddescriptor"]
                record_descriptor_identifier = tuple(record_descriptor_identifier)

                record_descriptor = self.descriptors.get(record_descriptor_identifier)
                if not record_descriptor:
                    raise RecordDescriptorNotFound(f"No RecordDescriptor found for: {record_descriptor_identifier}")

                del obj["_recorddescriptor"]
                del obj["_type"]
                for field_type, field_name in record_descriptor.get_field_tuples():
                    if field_type == "bytes":
                        obj[field_name] = base64.b64decode(obj[field_name])
                return record_descriptor.recordType(**obj)
            if _type == "recorddescriptor":
                data = obj["_data"]
                return RecordDescriptor._unpack(*data)
        return obj

    def pack(self, obj: Record | RecordDescriptor) -> str:
        return json.dumps(obj, default=self.pack_obj, indent=self.indent)

    def unpack(self, d: str) -> RecordDescriptor | Record:
        record_dict = json.loads(d, object_hook=self.unpack_obj)
        result = self.unpack_obj(record_dict)
        if isinstance(result, RecordDescriptor):
            self.register(result)
        return result
