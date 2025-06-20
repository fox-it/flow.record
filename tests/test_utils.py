import pytest

from flow.record.utils import boolean_argument


def test_boolean_argument() -> None:
    assert boolean_argument("True") is True
    assert boolean_argument("true") is True
    assert boolean_argument("trUe") is True
    assert boolean_argument("False") is False
    assert boolean_argument("false") is False
    assert boolean_argument("1") is True
    assert boolean_argument("0") is False
    assert boolean_argument("yes") is True
    assert boolean_argument("no") is False
    assert boolean_argument("y") is True
    assert boolean_argument("n") is False
    assert boolean_argument("on") is True
    assert boolean_argument("off") is False
    assert boolean_argument(True) is True
    assert boolean_argument(False) is False
    assert boolean_argument(1) is True
    assert boolean_argument(0) is False
    with pytest.raises(ValueError, match="Invalid boolean argument: .*"):
        boolean_argument("maybe")
