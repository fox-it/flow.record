from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from flow.record import RecordReader

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize("delimiter", [",", ";", "\t", "|"])
def test_csv_sniff(tmp_path: Path, delimiter: str) -> None:
    """Test CSV adapter with sniffing the dialect."""
    input_data = delimiter.join(["title", "year", "imdb"]) + "\n"
    input_data += delimiter.join(["The Shawshank Redemption", "1994", "tt0111161"]) + "\n"
    input_data += delimiter.join(["The Matrix", "1998", "tt0133093"]) + "\n"

    csv_path = tmp_path / "test.csv"
    csv_path.write_text(input_data)

    with RecordReader(csv_path) as reader:
        records = list(reader)
        assert len(records) == 2

        assert records[0].title == "The Shawshank Redemption"
        assert records[0].year == "1994"
        assert records[0].imdb == "tt0111161"

        assert records[1].title == "The Matrix"
        assert records[1].year == "1998"
        assert records[1].imdb == "tt0133093"


def test_csv_non_standard_headers(tmp_path: Path) -> None:
    """Test CSV adapter with header names that need to be cleaned up."""
    input_data = "Filename,Full Path,Size (bytes)\n"
    input_data += "passwd,/etc/passwd,2370\n"
    input_data += "shadow,/etc/shadow,1290\n"

    csv_path = tmp_path / "test.csv"
    csv_path.write_text(input_data)

    with RecordReader(csv_path) as reader:
        records = list(reader)
        assert len(records) == 2

        assert records[0].Filename == "passwd"
        assert records[0].Full_Path == "/etc/passwd"
        assert records[0].Size__bytes_ == "2370"

        assert records[1].Filename == "shadow"
        assert records[1].Full_Path == "/etc/shadow"
        assert records[1].Size__bytes_ == "1290"


def test_csv_read_reserved_fields(tmp_path: Path) -> None:
    """Test CSV adapter with reading reserved field names."""
    input_data = "_generated,_source,foo,bar\n"
    input_data += "2023-11-11 11:11:11.111111+11:11,single,hello,world\n"
    input_data += "2023-11-14T22:13:20+00:00,epoch,goodbye,planet\n"

    csv_path = tmp_path / "test.csv"
    csv_path.write_text(input_data)

    with RecordReader(csv_path) as reader:
        records = list(reader)
        assert len(records) == 2

        assert records[0]._generated == datetime.fromisoformat("2023-11-11 11:11:11.111111+11:11")
        assert records[0]._source == "single"
        assert records[0].foo == "hello"
        assert records[0].bar == "world"

        assert records[1]._generated == datetime.fromtimestamp(1700000000, tz=timezone.utc)
        assert records[1]._source == "epoch"
        assert records[1].foo == "goodbye"
        assert records[1].bar == "planet"
