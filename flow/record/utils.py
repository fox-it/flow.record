from __future__ import annotations

import base64
import os
import sys
from functools import wraps
from typing import BinaryIO, TextIO

_native = str
_unicode = type("")
_bytes = type(b"")


def get_stdout(binary: bool = False) -> TextIO | BinaryIO:
    """Return the stdout stream as binary or text stream.

    This function is the preferred way to get the stdout stream in flow.record.

    Arguments:
        binary: Whether to return the stream as binary stream.

    Returns:
        The stdout stream.
    """
    fp = getattr(sys.stdout, "buffer", sys.stdout) if binary else sys.stdout
    fp._is_stdout = True
    return fp


def get_stdin(binary: bool = False) -> TextIO | BinaryIO:
    """Return the stdin stream as binary or text stream.

    This function is the preferred way to get the stdin stream in flow.record.

    Arguments:
        binary: Whether to return the stream as binary stream.

    Returns:
        The stdin stream.
    """
    fp = getattr(sys.stdin, "buffer", sys.stdin) if binary else sys.stdin
    fp._is_stdin = True
    return fp


def is_stdout(fp: TextIO | BinaryIO) -> bool:
    """Returns True if ``fp`` is the stdout stream."""
    return fp in (sys.stdout, sys.stdout.buffer) or hasattr(fp, "_is_stdout")


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
