import json
import base64
import logging
from datetime import datetime

from . import fieldtypes
from .base import Record, RecordDescriptor
from .utils import EventHandler

log = logging.getLogger(__package__)


class JsonRecordPacker:
    def __init__(self, indent=None, pack_descriptors=True):
        self.descriptors = {}
        self.on_descriptor = EventHandler()
        self.pack_descriptors = pack_descriptors
        self.indent = indent

    def register(self, desc, notify=False):
        if not isinstance(desc, RecordDescriptor):
            raise Exception("Expected Record Descriptor")

        # Descriptor already known
        if desc.identifier in self.descriptors:
            return

        # versioned record descriptor
        self.descriptors[desc.identifier] = desc

        # for older non versioned records
        self.descriptors[desc.name] = desc

        if notify and self.on_descriptor:
            log.debug("JsonRecordPacker::on_descriptor {}".format(desc))
            self.on_descriptor(desc)

    def pack_obj(self, obj):
        if isinstance(obj, Record):
            if obj._desc.identifier not in self.descriptors:
                self.register(obj._desc, True)
            serial = obj._asdict()
            if self.pack_descriptors:
                serial["_type"] = "record"
                serial["_recorddescriptor"] = obj._desc.identifier

            # PYTHON2: Because "bytes" are also "str" we have to handle this here
            for (field_type, field_name) in obj._desc.get_field_tuples():
                if field_type == "bytes" and isinstance(serial[field_name], str):
                    serial[field_name] = base64.b64encode(serial[field_name]).decode()

            return serial
        if isinstance(obj, RecordDescriptor):
            serial = {
                "_type": "recorddescriptor",
                "_data": obj._pack(),
            }
            return serial
        if isinstance(obj, datetime):
            serial = obj.strftime("%Y-%m-%dT%H:%M:%S.%f")
            return serial
        if isinstance(obj, fieldtypes.digest):
            return {
                "md5": obj.md5,
                "sha1": obj.sha1,
                "sha256": obj.sha256,
            }
        if isinstance(obj, (fieldtypes.net.ipaddress, fieldtypes.net.ipnetwork)):
            return str(obj)
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()

        raise Exception("Unpackable type " + str(type(obj)))

    def unpack_obj(self, obj):
        if isinstance(obj, dict):
            _type = obj.get("_type", None)
            if _type == "record":
                record_descriptor_identifier = obj["_recorddescriptor"]
                record_descriptor_identifier = tuple(record_descriptor_identifier)
                record_descriptor = self.descriptors[record_descriptor_identifier]
                del obj["_recorddescriptor"]
                del obj["_type"]
                for (field_type, field_name) in record_descriptor.get_field_tuples():
                    if field_type == "bytes":
                        obj[field_name] = base64.b64decode(obj[field_name])
                result = record_descriptor.recordType(**obj)
                return result
            if _type == "recorddescriptor":
                data = obj["_data"]
                return RecordDescriptor._unpack(*data)
        return obj

    def pack(self, obj):
        return json.dumps(obj, default=self.pack_obj, indent=self.indent)

    def unpack(self, d):
        record_dict = json.loads(d, object_hook=self.unpack_obj)
        result = self.unpack_obj(record_dict)
        if isinstance(result, RecordDescriptor):
            self.register(result)
        return result
