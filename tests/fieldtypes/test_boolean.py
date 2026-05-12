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

    assert str(r.booltrue) == "True"
    assert str(r.boolfalse) == "False"

    assert repr(r.booltrue) == "True"
    assert repr(r.boolfalse) == "False"

    with pytest.raises(ValueError, match="Value not a valid boolean value"):
        TestRecord(2, -1)

    with pytest.raises(ValueError, match="invalid literal for int"):
        TestRecord("True", "False")
