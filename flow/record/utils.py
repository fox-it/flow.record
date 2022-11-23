import os
import sys
import base64
from functools import wraps

_native = str
_unicode = type("")
_bytes = type(b"")


def is_stdout(fp):
    return fp in (sys.stdout, sys.stdout.buffer)


def to_bytes(value):
    """Convert a value to a byte string."""
    if value is None or isinstance(value, _bytes):
        return value
    if isinstance(value, _unicode):
        return value.encode("utf-8")
    return _bytes(value)


def to_str(value):
    """Convert a value to a unicode string."""
    if value is None or isinstance(value, _unicode):
        return value
    if isinstance(value, _bytes):
        return value.decode("utf-8")
    return _unicode(value)


def to_native_str(value):
    """Convert a value to a native `str`."""
    if value is None or isinstance(value, _native):
        return value
    if isinstance(value, _unicode):
        # Python 2: unicode -> str
        return value.encode("utf-8")
    if isinstance(value, _bytes):
        # Python 3: bytes -> str
        return value.decode("utf-8")
    return _native(value)


def to_base64(value):
    """Convert a value to a base64 string."""
    return base64.b64encode(value).decode()


def catch_sigpipe(func):
    """Catches KeyboardInterrupt and BrokenPipeError (OSError 22 on Windows)."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print("Aborted!", file=sys.stderr)
            return 1
        except (BrokenPipeError, OSError) as e:
            exc_type = type(e)
            # Only catch BrokenPipeError or OSError 22
            if (exc_type is BrokenPipeError) or (exc_type is OSError and e.errno == 22):
                devnull = os.open(os.devnull, os.O_WRONLY)
                os.dup2(devnull, sys.stdout.fileno())
                return 1
            # Raise other exceptions
            raise

    return wrapper


class EventHandler:
    def __init__(self):
        self.handlers = []

    def add_handler(self, callback):
        self.handlers.append(callback)

    def remove_handler(self, callback):
        self.handlers.remove(callback)

    def __call__(self, *args, **kwargs):
        for h in self.handlers:
            h(*args, **kwargs)
