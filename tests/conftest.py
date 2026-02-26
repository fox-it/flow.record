import logging
import typing

import pytest

from flow.record.context import APP_CONTEXT


@pytest.fixture(autouse=True)
def reset_app_context() -> typing.Generator[None, None, None]:
    """This fixture resets the application context before each test."""
    token = APP_CONTEXT.set(None)
    yield
    APP_CONTEXT.reset(token)


@pytest.fixture(autouse=True)
def reset_logging() -> typing.Generator[None, None, None]:
    """Reset logging configuration between tests"""
    # Store initial state
    initial_handlers = logging.root.handlers.copy()
    initial_level = logging.root.level

    yield

    # Remove any handlers added during the test
    for handler in logging.root.handlers[:]:
        if handler not in initial_handlers:
            logging.root.removeHandler(handler)
            if hasattr(handler, "close"):
                try:
                    handler.close()
                except Exception:
                    pass

    # Reset level
    logging.root.setLevel(initial_level)
