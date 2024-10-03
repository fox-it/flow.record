from __future__ import annotations

import base64
import os
import sys
import warnings
from functools import wraps
from typing import BinaryIO, TextIO


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
    if value is None or isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(errors="surrogateescape")
    return bytes(value)


def to_str(value):
    """Convert a value to a unicode string."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode(errors="surrogateescape")
    return str(value)


def to_native_str(value):
    warnings.warn(
        (
            "The to_native_str() function is deprecated, "
            "this function will be removed in flow.record 3.20, "
            "use to_str() instead"
        ),
        DeprecationWarning,
    )
    return to_str(value)


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
