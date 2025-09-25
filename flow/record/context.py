from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

    from flow.record import Record
    from flow.record.selector import Selector

APP_CONTEXT: ContextVar[AppContext] = ContextVar("APP_CONTEXT")


def get_app_context() -> AppContext:
    """Retrieve the application context, creating it if it does not exist.

    Returns:
        The application context.
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


@dataclass(slots=True)
class AppContext:
    """Context for the application, holding metrics like amount of processed records."""

    read: int = 0
    matched: int = 0
    unmatched: int = 0
    source_count: int = 0
    source_total: int = 0


def match_record_with_context(record: Record, selector: Selector | None, context: AppContext) -> bool:
    """Return True if ``record`` matches the ``selector``, also keeps track of relevant metrics in ``context``.
    If selector is None, it will always return True.

    When calling this function, it also increases the ``context.read`` property.

    Arguments:
        record: The record to match against the selector.
        selector: The selector to use for matching.
        context: The context in which the record is being matched.

    Returns:
        True if record matches the selector, or if selector is None
    """
    context.read += 1
    if selector is None or selector.match(record):
        context.matched += 1
        return True
    context.unmatched += 1
    return False
