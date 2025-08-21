from pathlib import Path

from flow.record import RecordReader, RecordWriter
from flow.record.context import fresh_app_context, get_app_context
from tests._utils import generate_plain_records


def test_record_context() -> None:
    """Test the application context for record metrics."""
    ctx = get_app_context()
    assert ctx.read == 0
    assert ctx.matched == 0
    assert ctx.unmatched == 0


def test_record_context_metrics(tmp_path: Path) -> None:
    """Test the application context for record metrics."""
    ctx = get_app_context()

    with RecordWriter(tmp_path / "test.records") as writer:
        for record in generate_plain_records(2000):
            writer.write(record)

    assert ctx.read == 0
    assert ctx.matched == 0
    assert ctx.unmatched == 0

    list(RecordReader(tmp_path / "test.records", selector="r.number % 2 == 0 or r.number < 1337"))
    assert ctx.read == 2000
    assert ctx.matched == 1668
    assert ctx.unmatched == 332


def test_fresh_app_context(tmp_path: Path) -> None:
    ctx = get_app_context()

    with RecordWriter(tmp_path / "test.records") as writer:
        for record in generate_plain_records(2000):
            writer.write(record)

    assert ctx.read == 0
    assert ctx.matched == 0
    assert ctx.unmatched == 0

    list(RecordReader(tmp_path / "test.records", selector="r.number % 2 == 0 or r.number < 1337"))
    assert ctx.read == 2000
    assert ctx.matched == 1668
    assert ctx.unmatched == 332

    with fresh_app_context() as new_ctx:
        assert new_ctx.read == 0
        list(RecordReader(tmp_path / "test.records", selector="r.number == 42"))
        assert new_ctx.read == 2000
        assert new_ctx.matched == 1
        assert new_ctx.unmatched == 1999

    # check if the old context still holds
    assert ctx.read == 2000
    assert ctx.matched == 1668
    assert ctx.unmatched == 332

    # check if the old context still holds via get_app_context()
    ctx = get_app_context()
    assert ctx.read == 2000
    assert ctx.matched == 1668
    assert ctx.unmatched == 332
