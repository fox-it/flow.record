from __future__ import annotations

import re
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from flow.record import fieldtypes
from flow.record.adapter.xlsx import sanitize_fieldvalues

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def mock_openpyxl_package(monkeypatch: pytest.MonkeyPatch) -> Iterator[MagicMock]:
    with monkeypatch.context() as m:
        mock_openpyxl = MagicMock()
        mock_cell = MagicMock()
        mock_cell.ILLEGAL_CHARACTERS_RE = re.compile(r"[\000-\010]|[\013-\014]|[\016-\037]")
        m.setitem(sys.modules, "openpyxl", mock_openpyxl)
        m.setitem(sys.modules, "openpyxl.cell.cell", mock_cell)

        yield mock_openpyxl


def test_sanitize_field_values(mock_openpyxl_package: MagicMock) -> None:
    assert list(
        sanitize_fieldvalues(
            [
                7,
                datetime(1920, 11, 11, 13, 37, 0, tzinfo=timezone(timedelta(hours=2))),
                "James",
                b"Bond",
                b"\x00\x07",
                fieldtypes.net.ipaddress("13.37.13.37"),
                ["Shaken", "Not", "Stirred"],
                fieldtypes.posix_path("/home/user"),
                fieldtypes.posix_command("/bin/bash -c 'echo hello world'"),
                fieldtypes.windows_path("C:\\Users\\user\\Desktop"),
                fieldtypes.windows_command("C:\\Some.exe /?"),
            ]
        )
    ) == [
        7,
        datetime(1920, 11, 11, 11, 37, 0),  # UTC normalization  # noqa: DTZ001
        "James",
        'b"Bond"',  # When possible, encode bytes in a printable way
        "base64:AAc=",  # If not, base64 encode
        "13.37.13.37",  # Stringify an ip address
        "['Shaken', 'Not', 'Stirred']",  # Stringify a list
        "/home/user",  # Stringify a posix path
        "/bin/bash -c 'echo hello world'",  # Stringify a posix command
        "C:\\Users\\user\\Desktop",  # Stringify a windows path
        "C:\\Some.exe /?",  # Stringify a windows command
    ]
