from __future__ import annotations

from io import BytesIO

from flow.record import RecordDescriptor
from flow.record.adapter.text import TextWriter


def test_text_writer_write_surrogateescape() -> None:
    output = BytesIO()

    tw = TextWriter(
        path=output,
    )

    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("string", "name"),
        ],
    )

    # construct from 'bytes' but with invalid unicode bytes
    record = TestRecord(b"R\xc3\xa9\xeamy")
    tw.write(record)

    output.seek(0)
    data = output.read()

    assert data == b"<test/string name='R\xc3\xa9\\udceamy'>\n"
