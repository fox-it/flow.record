from __future__ import annotations

import base64
import os
import sys
import warnings
from functools import wraps
from typing import Any, BinaryIO, Callable, TextIO


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


def to_bytes(value: Any) -> bytes:
    """Convert a value to a byte string."""
    if value is None or isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode(errors="surrogateescape")
    return bytes(value)


def to_str(value: Any) -> str:
    """Convert a value to a unicode string."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode(errors="surrogateescape")
    return str(value)


def to_native_str(value: str) -> str:
    warnings.warn(
        (
            "The to_native_str() function is deprecated, "
            "this function will be removed in flow.record 3.20, "
            "use to_str() instead"
        ),
        DeprecationWarning,
        stacklevel=2,
    )
    return to_str(value)


def to_base64(value: str) -> str:
    """Convert a value to a base64 string."""
    return base64.b64encode(value).decode()


def catch_sigpipe(func: Callable[..., int]) -> Callable[..., int]:
    """Catches KeyboardInterrupt and BrokenPipeError (OSError 22 on Windows)."""

    @wraps(func)
    def wrapper(*args, **kwargs) -> int:
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

    def add_handler(self, callback: Callable[..., None]) -> None:
        self.handlers.append(callback)

    def remove_handler(self, callback: Callable[..., None]) -> None:
        self.handlers.remove(callback)

    def __call__(self, *args, **kwargs) -> None:
        for h in self.handlers:
            h(*args, **kwargs)


def boolean_argument(value: str | bool | int) -> bool:
    """Convert a string, boolean, or integer to a boolean value.

    This function interprets various string representations of boolean values,
    such as "true", "false", "1", "0", "yes", "no".
    It also accepts boolean and integer values directly.

    Arguments:
        value: The value to convert. Can be a string, boolean, or integer.

    Returns:
        bool: The converted boolean value.

    Raises:
        ValueError: If the value cannot be interpreted as a boolean.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        value = value.lower()
        if value in ("true", "1", "y", "yes", "on"):
            return True
        if value in ("false", "0", "n", "no", "off"):
            return False
    raise ValueError(f"Invalid boolean argument: {value}")
