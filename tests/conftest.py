import typing

import pytest

from flow.record.context import APP_CONTEXT


@pytest.fixture(autouse=True)
def reset_app_context() -> typing.Generator[None, None, None]:
    """This fixture resets the application context before each test."""
    token = APP_CONTEXT.set(None)
    yield
    APP_CONTEXT.reset(token)
