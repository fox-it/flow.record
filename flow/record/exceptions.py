class RecordDescriptorError(Exception):
    """Raised when there is an error constructing a record descriptor"""


class RecordDescriptorNotFound(Exception):
    """The specified record descriptor could not be found"""


class RecordAdapterNotFound(Exception):
    """Could not find a fitting RecordAdapter for a given input"""
