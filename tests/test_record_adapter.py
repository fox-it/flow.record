import datetime
import platform
import sys
from io import BytesIO

import pytest

from flow.record import (
    PathTemplateWriter,
    RecordAdapter,
    RecordArchiver,
    RecordDescriptor,
    RecordOutput,
    RecordReader,
    RecordStreamReader,
    RecordWriter,
)
from flow.record.adapter.stream import StreamReader, StreamWriter
from flow.record.base import (
    BZ2_MAGIC,
    GZIP_MAGIC,
    HAS_LZ4,
    HAS_ZSTD,
    LZ4_MAGIC,
    ZSTD_MAGIC,
)
from flow.record.selector import CompiledSelector, Selector

from ._utils import generate_records


def test_stream_writer_reader():
    fp = BytesIO()
    out = RecordOutput(fp)
    for rec in generate_records():
        out.write(rec)

    fp.seek(0)
    reader = RecordStreamReader(fp, selector="r.number in (2, 7)")
    records = []
    for rec in reader:
        records.append(rec)

    assert set([2, 7]) == set([r.number for r in records])


def test_recordstream_filelike_object():
    fp = BytesIO()
    out = RecordOutput(fp)
    for rec in generate_records():
        out.write(rec)

    fp.seek(0)
    reader = RecordReader(fileobj=fp, selector="r.number in (6, 9)")

    #  The record reader should automatically have created a 'StreamReader' to handle the Record Stream.
    assert isinstance(reader, StreamReader)

    # Verify if selector worked and records are the same
    records = []
    for rec in reader:
        records.append(rec)

    assert set([6, 9]) == set([r.number for r in records])


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_file_writer_reader(tmpdir, PSelector):
    p = tmpdir.join("test.records")
    with RecordWriter(p) as out:
        for rec in generate_records():
            out.write(rec)
        out.flush()

    selector = PSelector("r.number in (1, 3)")
    with RecordReader(p, selector=selector) as reader:
        numbers = [r.number for r in reader]
        assert set([1, 3]) == set(numbers)


@pytest.mark.parametrize("compression", ["gz", "bz2", "lz4", "zstd"])
def test_compressed_writer_reader(tmpdir, compression):
    """Test auto compression of Record files."""
    if compression == "lz4" and not HAS_LZ4:
        pytest.skip("lz4 module not installed")
    if compression == "zstd" and not HAS_ZSTD:
        pytest.skip("zstandard module not installed")

    if compression == "lz4" and platform.python_implementation() == "PyPy":
        pytest.skip("lz4 module not supported on PyPy")
    if compression == "zstd" and platform.python_implementation() == "PyPy":
        pytest.skip("zstandard module not supported on PyPy")

    p = tmpdir.mkdir("{}-test".format(compression))
    path = str(p.join("test.records.{}".format(compression)))

    assert path.endswith(".{}".format(compression))

    count = 100
    writer = RecordWriter(path)
    for rec in generate_records(count):
        writer.write(rec)
    # writer needs to be closed to flush current buffers
    writer.close()

    # test if the file we wrote is actually correct format
    with open(path, "rb") as f:
        if compression == "gz":
            assert f.read(2) == GZIP_MAGIC
        elif compression == "bz2":
            assert f.read(3) == BZ2_MAGIC
        elif compression == "lz4":
            assert f.read(4) == LZ4_MAGIC
        elif compression == "zstd":
            assert f.read(4) == ZSTD_MAGIC

    # Read the records from compressed file
    reader = RecordReader(path)
    numbers = []
    for rec in reader:
        numbers.append(rec.number)

    assert numbers == list(range(count))

    # Using a file-handle instead of a path should also work
    with open(path, "rb") as fh:
        reader = RecordReader(fileobj=fh)
        numbers = []
        for rec in reader:
            numbers.append(rec.number)

        assert numbers == list(range(count))


def test_path_template_writer(tmpdir):
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "id"),
        ],
    )

    records = [
        TestRecord(id=1, _generated=datetime.datetime(2017, 12, 6, 22, 10)),
        TestRecord(id=2, _generated=datetime.datetime(2017, 12, 6, 23, 59)),
        TestRecord(id=3, _generated=datetime.datetime(2017, 12, 7, 00, 00)),
    ]

    p = tmpdir.mkdir("test")
    writer = PathTemplateWriter(str(p.join("{name}-{ts:%Y%m%dT%H}.records.gz")), name="test")
    for rec in records:
        writer.write(rec)
    writer.close()

    assert p.join("test-20171206T22.records.gz").check(file=1)
    assert p.join("test-20171206T23.records.gz").check(file=1)
    assert p.join("test-20171207T00.records.gz").check(file=1)

    # Test rotation/renaming
    before = p.listdir()
    writer = PathTemplateWriter(str(p.join("{name}-{ts:%Y%m%dT%H}.records.gz")), name="test")
    for rec in records:
        writer.write(rec)
    writer.close()
    after = p.listdir()

    assert set(before).issubset(set(after))
    assert len(after) > len(before)
    assert len(before) == 3
    assert len(after) == 6


def test_record_archiver(tmpdir):
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "id"),
        ],
    )

    records = [
        TestRecord(id=1, _generated=datetime.datetime(2017, 12, 6, 22, 10)),
        TestRecord(id=2, _generated=datetime.datetime(2017, 12, 6, 23, 59)),
        TestRecord(id=3, _generated=datetime.datetime(2017, 12, 7, 00, 00)),
    ]

    p = tmpdir.mkdir("test")

    writer = RecordArchiver(p, name="archive-test")
    for rec in records:
        writer.write(rec)
    writer.close()

    assert p.join("2017/12/06").check(dir=1)
    assert p.join("2017/12/07").check(dir=1)

    assert p.join("2017/12/06/archive-test-20171206T22.records.gz").check(file=1)
    assert p.join("2017/12/06/archive-test-20171206T23.records.gz").check(file=1)
    assert p.join("2017/12/07/archive-test-20171207T00.records.gz").check(file=1)

    # test archiving
    before = p.join("2017/12/06").listdir()
    writer = RecordArchiver(p, name="archive-test")
    for rec in records:
        writer.write(rec)
    writer.close()
    after = p.join("2017/12/06").listdir()

    assert set(before).issubset(set(after))
    assert len(after) > len(before)
    assert len(before) == 2
    assert len(after) == 4


def test_record_writer_stdout():
    writer = RecordWriter()
    assert writer.fp == getattr(sys.stdout, "buffer", sys.stdout)

    writer = RecordWriter(None)
    assert writer.fp == getattr(sys.stdout, "buffer", sys.stdout)

    writer = RecordWriter("")
    assert writer.fp == getattr(sys.stdout, "buffer", sys.stdout)

    # We cannot test RecordReader() because it will read from stdin during init
    # reader = RecordReader()
    # assert reader.fp == sys.stdin


def test_record_adapter_archive(tmpdir):
    # archive some records, using "testing" as name
    writer = RecordWriter("archive://{}?name=testing".format(tmpdir))
    dt = datetime.datetime.now(datetime.timezone.utc)
    count = 0
    for rec in generate_records():
        writer.write(rec)
        count += 1
    writer.close()

    # defaults to always archive by /YEAR/MONTH/DAY/ dir structure
    outdir = tmpdir.join("{ts:%Y/%m/%d}".format(ts=dt))
    assert len(outdir.listdir())

    # read the archived records and test filename and counts
    count2 = 0
    for fname in outdir.listdir():
        assert fname.basename.startswith("testing-")
        for rec in RecordReader(str(fname)):
            count2 += 1
    assert count == count2


def test_record_pathlib(tmp_path):
    # Test support for Pathlib/PathLike objects
    writer = RecordWriter(tmp_path / "test.records")
    for rec in generate_records(100):
        writer.write(rec)
    writer.close()

    reader = RecordReader(tmp_path / "test.records")
    assert len([rec for rec in reader]) == 100
    assert not isinstance(tmp_path / "test.records", str)


def test_record_pathlib_contextmanager(tmp_path):
    with RecordWriter(tmp_path / "test.records") as writer:
        for rec in generate_records(100):
            writer.write(rec)

    with RecordReader(tmp_path / "test.records") as reader:
        assert len([rec for rec in reader]) == 100
        assert not isinstance(tmp_path / "test.records", str)


def test_record_pathlib_contextmanager_double_close(tmp_path):
    with RecordWriter(tmp_path / "test.records") as writer:
        for rec in generate_records(100):
            writer.write(rec)
        writer.close()

    with RecordReader(tmp_path / "test.records") as reader:
        assert len([rec for rec in reader]) == 100
        reader.close()


def test_record_invalid_recordstream(tmp_path):
    path = str(tmp_path / "invalid_records")
    with open(path, "wb") as f:
        f.write(b"INVALID RECORD STREAM FILE")

    with pytest.raises(IOError):
        with RecordReader(path) as reader:
            for r in reader:
                assert r


@pytest.mark.parametrize(
    "adapter,contains",
    [
        ("csvfile", (b"5,hello,world", b"count,foo,bar,")),
        ("jsonfile", (b'"count": 5',)),
        ("text", (b"count=5",)),
        ("line", (b"count = 5", b"--[ RECORD 5 ]--")),
    ],
)
def test_record_adapter(adapter, contains, tmp_path):
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "count"),
            ("string", "foo"),
            ("string", "bar"),
        ],
    )

    # construct the RecordWriter with uri
    path = tmp_path / "output"
    uri = "{adapter}://{path!s}".format(adapter=adapter, path=path)

    # test parametrized contains
    with RecordWriter(uri) as writer:
        for i in range(10):
            rec = TestRecord(count=i, foo="hello", bar="world")
            writer.write(rec)
    for pattern in contains:
        assert pattern in path.read_bytes()

    # test include (excludes everything else except in include)
    with RecordWriter("{}?fields=count".format(uri)) as writer:
        for i in range(10):
            rec = TestRecord(count=i, foo="hello", bar="world")
            writer.write(rec)

    # test exclude
    with RecordWriter("{}?exclude=count".format(uri)) as writer:
        for i in range(10):
            rec = TestRecord(count=i, foo="hello", bar="world")
            writer.write(rec)


def test_text_record_adapter(capsys):
    TestRecordWithFooBar = RecordDescriptor(
        "test/record",
        [
            ("string", "name"),
            ("string", "foo"),
            ("string", "bar"),
        ],
    )
    TestRecordWithoutFooBar = RecordDescriptor(
        "test/record2",
        [
            ("string", "name"),
        ],
    )
    format_spec = "Hello {name}, {foo} is {bar}!"
    with RecordWriter(f"text://?format_spec={format_spec}") as writer:
        # Format string with existing variables
        rec = TestRecordWithFooBar(name="world", foo="foo", bar="bar")
        writer.write(rec)
        out, err = capsys.readouterr()
        assert "Hello world, foo is bar!\n" == out

        # Format string with non-existing variables
        rec = TestRecordWithoutFooBar(name="planet")
        writer.write(rec)
        out, err = capsys.readouterr()
        assert "Hello planet, {foo} is {bar}!\n" == out


def test_recordstream_header(tmp_path):
    # Create and delete a RecordWriter, with nothing happening
    p = tmp_path / "out.records"
    writer = RecordWriter(p)
    del writer
    assert p.read_bytes() == b""

    # RecordWriter via context manager, always flushes and closes afterwards
    p = tmp_path / "out2.records"
    with RecordWriter(p) as writer:
        pass
    assert p.read_bytes() == b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n"

    # Manual create of RecordWriter with no records and close (no flush)
    p = tmp_path / "out3.records"
    writer = RecordWriter(p)
    writer.close()
    assert p.read_bytes() == b""

    # Manual RecordWriter with no records but flush and close
    p = tmp_path / "out3.records"
    writer = RecordWriter(p)
    writer.flush()
    writer.close()
    assert p.read_bytes() == b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n"

    # Manual RecordWriter with some records written, we flush to ensure output due to buffering
    p = tmp_path / "out4.records"
    writer = RecordWriter(p)
    writer.write(next(generate_records()))
    writer.flush()
    del writer
    assert p.read_bytes().startswith(b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n")


def test_recordstream_header_stdout(capsysbinary):
    with RecordWriter() as writer:
        pass
    out, err = capsysbinary.readouterr()
    assert out == b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n"

    writer = RecordWriter()
    del writer
    out, err = capsysbinary.readouterr()
    assert out == b""

    writer = RecordWriter()
    writer.close()
    out, err = capsysbinary.readouterr()
    assert out == b""

    writer = RecordWriter()
    writer.flush()
    writer.close()
    out, err = capsysbinary.readouterr()
    assert out == b"\x00\x00\x00\x0f\xc4\rRECORDSTREAM\n"


def test_csv_adapter_lineterminator(capsysbinary):
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "count"),
            ("string", "foo"),
            ("string", "bar"),
        ],
    )

    with RecordWriter(r"csvfile://?lineterminator=\r\n&exclude=_source,_classification,_generated,_version") as writer:
        for i in range(3):
            rec = TestRecord(count=i, foo="hello", bar="world")
            writer.write(rec)
    out, _ = capsysbinary.readouterr()
    assert out == b"count,foo,bar\r\n0,hello,world\r\n1,hello,world\r\n2,hello,world\r\n"

    with RecordWriter(r"csvfile://?lineterminator=\n&exclude=_source,_classification,_generated,_version") as writer:
        for i in range(3):
            rec = TestRecord(count=i, foo="hello", bar="world")
            writer.write(rec)
    out, _ = capsysbinary.readouterr()
    assert out == b"count,foo,bar\n0,hello,world\n1,hello,world\n2,hello,world\n"

    with RecordWriter(r"csvfile://?lineterminator=@&exclude=_source,_classification,_generated,_version") as writer:
        for i in range(3):
            rec = TestRecord(count=i, foo="hello", bar="world")
            writer.write(rec)
    out, _ = capsysbinary.readouterr()
    assert out == b"count,foo,bar@0,hello,world@1,hello,world@2,hello,world@"


def test_csvfilereader(tmp_path):
    path = tmp_path / "test.csv"
    with path.open("wb") as f:
        f.write(b"count,foo,bar\r\n")
        for i in range(10):
            f.write(f"{i},hello,world\r\n".encode())

    with RecordReader(f"csvfile://{path}") as reader:
        for i, rec in enumerate(reader):
            assert rec.count == str(i)
            assert rec.foo == "hello"
            assert rec.bar == "world"

    with RecordReader(f"csvfile://{path}", selector="r.count == '2'") as reader:
        for i, rec in enumerate(reader):
            assert rec.count == "2"


def test_file_like_writer_reader() -> None:
    test_buf = BytesIO()

    adapter = RecordAdapter(fileobj=test_buf, out=True)

    assert isinstance(adapter, StreamWriter)

    # Add mock records
    test_records = list(generate_records(10))
    for record in test_records:
        adapter.write(record)

    adapter.flush()

    # Grab the bytes before closing the BytesIO object.
    read_buf = BytesIO(test_buf.getvalue())

    # Close the writer and assure the object has been closed
    adapter.close()

    # Verify if the written record stream is something we can read
    reader = RecordAdapter(fileobj=read_buf)
    read_records = list(reader)
    assert len(read_records) == 10
    for idx, record in enumerate(read_records):
        assert record == test_records[idx]
