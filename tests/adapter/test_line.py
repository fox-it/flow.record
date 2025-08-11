from __future__ import annotations

from io import BytesIO

from flow.record import RecordDescriptor
from flow.record.adapter.line import LineWriter


def test_line_writer_write_surrogateescape() -> None:
    output = BytesIO()

    lw = LineWriter(
        path=output,
        fields="name",
    )

    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("string", "name"),
        ],
    )

    # construct from 'bytes' but with invalid unicode bytes
    record = TestRecord(b"R\xc3\xa9\xeamy")
    lw.write(record)

    output.seek(0)
    data = output.read()

    assert data == b"--[ RECORD 1 ]--\nname = R\xc3\xa9\xeamy\n"
