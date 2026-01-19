from __future__ import annotations

import pytest

from flow.record.base import RecordDescriptor


def test_boolean() -> None:
    TestRecord = RecordDescriptor(
        "test/boolean",
        [
            ("boolean", "booltrue"),
            ("boolean", "boolfalse"),
        ],
    )

    r = TestRecord(True, False)
    assert bool(r.booltrue) is True
    assert bool(r.boolfalse) is False

    r = TestRecord(1, 0)
    assert bool(r.booltrue) is True
    assert bool(r.boolfalse) is False

    assert str(r.booltrue) == "1"
    assert str(r.boolfalse) == "0"

    assert repr(r.booltrue) == "1"
    assert repr(r.boolfalse) == "0"

    with pytest.raises(ValueError, match="Value not a valid boolean value"):
        r = TestRecord(2, -1)

    with pytest.raises(ValueError, match="invalid literal for int"):
        r = TestRecord("True", "False")
