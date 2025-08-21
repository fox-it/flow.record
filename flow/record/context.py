from __future__ import annotations

import sys
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

APP_CONTEXT: ContextVar[AppContext] = ContextVar("APP_CONTEXT")


def get_app_context() -> AppContext:
    """Retrieve the application context, creating it if it does not exist.

    Returns:
        AppContext: The application context.
    """
    if (ctx := APP_CONTEXT.get(None)) is None:
        ctx = AppContext()
        APP_CONTEXT.set(ctx)
    return ctx


@contextmanager
def fresh_app_context() -> Generator[AppContext, None, None]:
    """Create a fresh application context for the duration of the with block."""
    token = APP_CONTEXT.set(AppContext())
    try:
        yield APP_CONTEXT.get()
    finally:
        APP_CONTEXT.reset(token)


# Use slots=True on dataclass for better performance which requires Python 3.10 or later.
# This can be removed when we drop support for Python 3.9.
if sys.version_info >= (3, 10):
    app_dataclass = dataclass(slots=True)  # novermin
else:
    app_dataclass = dataclass


@app_dataclass
class AppContext:
    """Context for the application, holding metrics like amount of processed records."""

    read: int = 0
    matched: int = 0
    excluded: int = 0
    source_count: int = 0
    source_total: int = 0
