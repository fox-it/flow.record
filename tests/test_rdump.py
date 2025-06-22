from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import timezone
from pathlib import Path
from unittest import mock

import pytest

import flow.record.fieldtypes
from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.adapter.line import field_types_for_record_descriptor
from flow.record.fieldtypes import flow_record_tz
from flow.record.tools import rdump


def test_rdump_pipe(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
            ("string", "foo"),
        ],
    )

    path = tmp_path / "test.records"
    writer = RecordWriter(path)

    for i in range(10):
        writer.write(TestRecord(count=i, foo="bar"))
    writer.close()

    # validate input
    args = ["rdump", str(path)]
    res = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = res.communicate()
    assert len(stdout.splitlines()) == 10

    # rdump test.records | wc -l
    p1 = subprocess.Popen(["rdump", str(path)], stdout=subprocess.PIPE)

    # counting lines on Windows: https://devblogs.microsoft.com/oldnewthing/20110825-00/?p=9803
    p2_cmd = ["find", "/c", "/v", ""] if platform.system() == "Windows" else ["wc", "-l"]
    p2 = subprocess.Popen(p2_cmd, stdin=p1.stdout, stdout=subprocess.PIPE)

    stdout, stderr = p2.communicate()
    assert stdout.strip() == b"10"

    # (binary) rdump test.records -w - | rdump -s 'r.count == 5'
    p1 = subprocess.Popen(["rdump", str(path), "-w", "-"], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(
        ["rdump", "-s", "r.count == 5"],
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
    )
    stdout, stderr = p2.communicate()
    assert stdout.strip() in (b"<test/record count=5 foo='bar'>", b"<test/record count=5L foo=u'bar'>")

    # (printer) rdump test.records | rdump -s 'r.count == 5'
    p1 = subprocess.Popen(["rdump", str(path)], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(
        ["rdump", "-s", "r.count == 5"],
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = p2.communicate()
    assert stdout.strip() == b""
    assert b"Are you perhaps entering record text, rather than a record stream?" in stderr.strip()

    # rdump test.records -w - | rdump -s 'r.count in (1, 3, 9)' -w filtered.records
    path2 = tmp_path / "filtered.records"
    p1 = subprocess.Popen(["rdump", str(path), "-w", "-"], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(
        ["rdump", "-s", "r.count in (1, 3, 9)", "-w", str(path2)],
        stdin=p1.stdout,
    )
    stdout, stderr = p2.communicate()

    reader = RecordReader(path2)
    records = list(reader)
    assert len(records) == 3
    assert {r.count for r in records} == {1, 3, 9}


def test_rdump_format_template(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
            ("string", "foo"),
        ],
    )

    path = tmp_path / "test.records"
    writer = RecordWriter(path)

    # generate some test records
    for i in range(10):
        writer.write(TestRecord(count=i, foo="bar"))
    writer.close()

    # validate output with -f
    args = ["rdump", str(path), "-f", "TEST: {count},{foo}"]
    print(args)
    res = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = res.communicate()
    for i, line in enumerate(stdout.decode().splitlines()):
        assert line == f"TEST: {i},bar"


def test_rdump_json(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
            ("string", "foo"),
            ("bytes", "data"),
            ("net.ipaddress", "ip"),
            ("net.ipnetwork", "subnet"),
            ("digest", "digest"),
        ],
    )

    record_path = tmp_path / "test.records"
    writer = RecordWriter(record_path)

    # generate some test records
    for i in range(10):
        data = str(i).encode()
        md5 = hashlib.md5(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        writer.write(
            TestRecord(
                count=i,
                foo="bar" * i,
                data=b"\x00\x01\x02\x03--" + data,
                ip=f"172.16.0.{i}",
                subnet=f"192.168.{i}.0/24",
                digest=(md5, sha1, sha256),
            )
        )
    writer.close()

    # dump records as JSON lines
    args = ["rdump", str(record_path), "-w", "jsonfile://-?descriptors=true"]
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()

    assert process.returncode == 0

    # Basic validations in stdout
    for i in range(10):
        assert base64.b64encode(f"\x00\x01\x02\x03--{i}".encode()) in stdout
        assert f"192.168.{i}.0/24".encode() in stdout
        assert f"172.16.0.{i}".encode() in stdout
        assert ("bar" * i).encode() in stdout

    # Load json using json.loads() and validate key values
    for i, line in enumerate(stdout.splitlines()):
        json_dict = json.loads(line)
        assert json_dict
        if i == 0:
            assert "_type" in json_dict
            assert json_dict["_type"] == "recorddescriptor"
        else:
            count = i - 1  # fix offset as first line is the recorddescriptor information
            data = str(count).encode()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            assert json_dict["count"] == count
            assert json_dict["foo"] == "bar" * count
            assert json_dict["data"] == base64.b64encode(f"\x00\x01\x02\x03--{count}".encode()).decode()
            assert json_dict["ip"] == f"172.16.0.{count}"
            assert json_dict["subnet"] == f"192.168.{count}.0/24"
            assert json_dict["digest"]["md5"] == md5
            assert json_dict["digest"]["sha1"] == sha1
            assert json_dict["digest"]["sha256"] == sha256

    # Write jsonlines to file
    path = tmp_path / "records.jsonl"
    path.write_bytes(stdout)
    json_path = f"jsonfile://{path}"

    # Read records from json and original records file and validate
    for path in (json_path, record_path):
        with RecordReader(path) as reader:
            for i, record in enumerate(reader):
                data = str(i).encode()
                md5 = hashlib.md5(data).hexdigest()
                sha1 = hashlib.sha1(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                assert record.count == i
                assert record.ip == f"172.16.0.{i}"
                assert record.subnet == f"192.168.{i}.0/24"
                assert record.data == b"\x00\x01\x02\x03--" + data
                assert record.digest.md5 == md5
                assert record.digest.sha1 == sha1
                assert record.digest.sha256 == sha256
                assert record.foo == "bar" * i


def test_rdump_json_no_descriptors(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
            ("string", "foo"),
            ("bytes", "data"),
            ("net.ipaddress", "ip"),
            ("net.ipnetwork", "subnet"),
            ("digest", "digest"),
        ],
    )

    # generate some test records
    record_path = tmp_path / "test.records"
    with RecordWriter(record_path) as writer:
        for i in range(10):
            data = str(i).encode()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            writer.write(
                TestRecord(
                    count=i,
                    foo="bar" * i,
                    data=b"\x00\x01\x02\x03--" + data,
                    ip=f"172.16.0.{i}",
                    subnet=f"192.168.{i}.0/24",
                    digest=(md5, sha1, sha256),
                )
            )

    # dump records as JSON lines
    args = ["rdump", str(record_path), "--jsonlines"]
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()

    assert process.returncode == 0
    assert stderr is None

    for i, line in enumerate(stdout.splitlines()):
        json_dict = json.loads(line)
        assert json_dict
        assert "_type" not in json_dict
        assert "_recorddescriptor" not in json_dict
        assert "_source" in json_dict
        data = str(i).encode()
        assert json_dict["data"] == base64.b64encode(b"\x00\x01\x02\x03--" + data).decode()
        assert json_dict["ip"] == f"172.16.0.{i}"
        assert json_dict["subnet"] == f"192.168.{i}.0/24"
        assert json_dict["digest"]["md5"] == hashlib.md5(data).hexdigest()
        assert json_dict["digest"]["sha1"] == hashlib.sha1(data).hexdigest()
        assert json_dict["digest"]["sha256"] == hashlib.sha256(data).hexdigest()


def test_rdump_format_spec_hex(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("bytes", "data"),
        ],
    )

    # generate a test record
    test_record = TestRecord(
        data=b"\x00\x01--hello world--\xee\xff",
    )

    # write the test record so rdump can read it
    record_path = tmp_path / "test.records"
    with RecordWriter(record_path) as writer:
        writer.write(test_record)

    # rdump with --format string using our hex format spec
    args = [
        "rdump",
        str(record_path),
        "--format",
        "hex:{data:hex} HEX:{data:HEX} x:{data:x} X:{data:X} #x:{data:#x} #X:{data:#X}",
    ]
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()

    assert process.returncode == 0
    assert stderr is None
    assert stdout.rstrip() == b" ".join(
        [
            b"hex:00012d2d68656c6c6f20776f726c642d2deeff",
            b"HEX:00012D2D68656C6C6F20776F726C642D2DEEFF",
            b"x:00012d2d68656c6c6f20776f726c642d2deeff",
            b"X:00012D2D68656C6C6F20776F726C642D2DEEFF",
            b"#x:0x00012d2d68656c6c6f20776f726c642d2deeff",
            b"#X:0x00012D2D68656C6C6F20776F726C642D2DEEFF",
        ]
    )


def test_rdump_list_adapters() -> None:
    args = [
        "rdump",
        "--list-adapters",
    ]
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()

    assert process.returncode == 0
    assert stderr is None
    for adapter in ("stream", "line", "text", "jsonfile", "csvfile"):
        assert f"{adapter}:{os.linesep}".encode() in stdout


@pytest.mark.parametrize(
    "filename",
    [
        "output",
        "output.records",
        "output.records.gz",
        "output.records.bz2",
        "output.records.json",
        "output.records.jsonl",
    ],
)
def test_rdump_split(tmp_path: Path, filename: str) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
        ],
    )

    # generate test records so rdump can read it
    record_path = tmp_path / "input.records"
    with RecordWriter(record_path) as writer:
        for i in range(100):
            writer.write(TestRecord(count=i))

    # rdump --split=10 -w output.records
    output_path = tmp_path / filename
    rdump.main([str(record_path), "--split=10", "-w", str(output_path)])

    # verify output
    for i in range(10):
        path = output_path.with_suffix(f".{i:02d}{output_path.suffix}")
        assert path.exists()
        with RecordReader(path) as reader:
            for j, record in enumerate(reader):
                assert record.count == i * 10 + j


def test_rdump_split_suffix_length(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
        ],
    )

    # generate test records so rdump can read it
    record_path = tmp_path / "input.records"
    with RecordWriter(record_path) as writer:
        for i in range(100):
            writer.write(TestRecord(count=i))

    # rdump --split=10 --suffix-length=4 -w output.records
    output_path = tmp_path / "output.records"
    rdump.main([str(record_path), "--split=10", "--suffix-length=4", "-w", str(output_path)])
    for i in range(10):
        output_path = tmp_path / f"output.{i:04d}.records"
        assert output_path.exists()


@pytest.mark.parametrize(
    ("scheme", "first_line"),
    [
        ("csvfile://", b"count,"),
        ("jsonfile://", b"recorddescriptor"),
        ("jsonfile://?descriptors=false", b"X-TEST-"),
        ("text://", b"<test/record"),
    ],
)
def test_rdump_split_using_uri(
    tmp_path: Path, scheme: str, first_line: bytes, capsysbinary: pytest.CaptureFixture
) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "count"),
        ],
    )

    # generate test records so rdump can read it
    record_path = tmp_path / "input.records"
    with RecordWriter(record_path) as writer:
        for i in range(10):
            writer.write(TestRecord(count=f"X-TEST-{i}-TEST-X"))

    # test stdout: rdump --split=10 $scheme
    rdump.main([str(record_path), "--split=10", "-w", scheme])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert b"X-TEST-9-TEST-X" in captured.out.splitlines()[-1]

    # test file: rdump --split=10 scheme://output
    output_path = tmp_path / "output"
    scheme, _, options = scheme.partition("?")
    cmd = [str(record_path), "--split=5", "-w", f"{scheme}{output_path}?{options}"]
    rdump.main(cmd)

    # verify output
    for i in range(2):
        path = output_path.with_suffix(f".{i:02d}{output_path.suffix}")
        assert path.exists()
        with path.open("rb") as f:
            assert first_line in next(f)


def test_rdump_split_without_writer(capsysbinary: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit):
        rdump.main(["--split=10"])
    captured = capsysbinary.readouterr()
    assert b"error: --split only makes sense in combination with -w/--writer" in captured.err


def test_rdump_csv(tmp_path: Path, capsysbinary: pytest.CaptureFixture) -> None:
    path = tmp_path / "test.csv"
    with path.open("w") as f:
        f.write("count,text\n")
        f.write("1,hello\n")
        f.write("2,world\n")
        f.write("3,bar\n")

    rdump.main([str(path)])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert captured.out.splitlines() == [
        b"<csv/reader count='1' text='hello'>",
        b"<csv/reader count='2' text='world'>",
        b"<csv/reader count='3' text='bar'>",
    ]


def test_rdump_headerless_csv(tmp_path: Path, capsysbinary: pytest.CaptureFixture) -> None:
    # write out headerless CSV file
    path = tmp_path / "test.csv"
    with path.open("w") as f:
        f.write("1,hello\n")
        f.write("2,world\n")
        f.write("3,bar\n")

    # manualy specify CSV fields
    rdump.main([f"csvfile://{path}?fields=count,text"])
    captured = capsysbinary.readouterr()
    assert captured.err == b""
    assert captured.out.splitlines() == [
        b"<csv/reader count='1' text='hello'>",
        b"<csv/reader count='2' text='world'>",
        b"<csv/reader count='3' text='bar'>",
    ]


def test_rdump_stdin_peek(tmp_path: Path) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "count"),
            ("string", "foo"),
        ],
    )

    path = tmp_path / "test.records"
    writer = RecordWriter(path)
    # generate some test records
    for i in range(10):
        writer.write(TestRecord(count=i, foo="bar"))
    writer.close()

    gzip_file_path = path.with_suffix(".records.gz")

    # Gzip compress records file (using python)
    with gzip.GzipFile(gzip_file_path, mode="wb") as gzip_file:
        gzip_file.write(path.read_bytes())

    on_windows = platform.system() == "Windows"
    read_command = "cat" if not on_windows else "type"

    # Rdump should transparently decompress and select the correct adapter
    # Shell gets used on windows for `type` to be available
    p1 = subprocess.Popen([read_command, gzip_file_path], stdout=subprocess.PIPE, shell=on_windows)

    # For windows compatibility we use an absolute path of the rdump executable
    rdump = shutil.which("rdump", path=Path(sys.executable).parent)
    p2 = subprocess.Popen(
        [rdump, "-s", "r.count == 5"],
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, _ = p2.communicate()

    assert stdout.strip() in (b"<test/record count=5 foo='bar'>", b"<test/record count=5L foo=u'bar'>")


@pytest.mark.parametrize(
    ("total_records", "count", "skip", "expected_numbers"),
    [
        (10, None, 2, [2, 3, 4, 5, 6, 7, 8, 9]),
        (10, 3, None, [0, 1, 2]),
        (10, 2, 3, [3, 4]),
        (10, None, 9, [9]),
        (10, None, 10, []),
    ],
)
def test_rdump_count_and_skip(
    tmp_path: Path,
    capsysbinary: pytest.CaptureFixture,
    total_records: int,
    count: int | None,
    skip: int,
    expected_numbers: list[int],
) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "number"),
            ("string", "foo"),
        ],
    )

    # Write test records to a file
    full_set_path = tmp_path / "test_full_set.records"
    with RecordWriter(full_set_path) as writer:
        for i in range(total_records):
            record = TestRecord(number=i, foo="bar" + "baz" * i)
            writer.write(record)

    rdump_parameters = []
    if count is not None:
        rdump_parameters.append(f"--count={count}")
    if skip is not None:
        rdump_parameters.append(f"--skip={skip}")

    rdump.main([str(full_set_path), "--csv", "-F", "number", *rdump_parameters])
    captured = capsysbinary.readouterr()
    assert captured.err == b""

    # Skip csv header
    record_lines = captured.out.splitlines()[1:]

    # Convert numbers to integers and validate
    numbers = list(map(int, record_lines))
    assert numbers == expected_numbers

    # Write records using --skip and --count to a new file
    subset_path = tmp_path / "test_subset.records"
    rdump.main([str(full_set_path), "-w", str(subset_path), *rdump_parameters])

    # Read records from new file and validate
    numbers = None
    with RecordReader(subset_path) as reader:
        numbers = [rec.number for rec in reader]
    assert numbers == expected_numbers


@pytest.mark.parametrize(
    ("date_str", "tz", "expected_date_str"),
    [
        ("2023-08-02T22:28:06.12345+01:00", None, "2023-08-02 21:28:06.123450+00:00"),
        ("2023-08-02T22:28:06.12345+01:00", "NONE", "2023-08-02 22:28:06.123450+01:00"),
        ("2023-08-02T22:28:06.12345-08:00", "NONE", "2023-08-02 22:28:06.123450-08:00"),
        ("2023-08-02T20:51:32.123456+00:00", "Europe/Amsterdam", "2023-08-02 22:51:32.123456+02:00"),
        ("2023-08-02T20:51:32.123456+00:00", "America/New_York", "2023-08-02 16:51:32.123456-04:00"),
    ],
)
@pytest.mark.parametrize(
    "rdump_params",
    [
        [],
        ["--mode=csv"],
        ["--mode=line"],
    ],
)
def test_flow_record_tz_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    date_str: str,
    tz: str,
    expected_date_str: str,
    rdump_params: list[str],
) -> None:
    TestRecord = RecordDescriptor(
        "test/flow_record_tz",
        [
            ("datetime", "stamp"),
        ],
    )
    with RecordWriter(tmp_path / "test.records") as writer:
        writer.write(TestRecord(stamp=date_str))

    env_dict = {}
    if tz is not None:
        env_dict["FLOW_RECORD_TZ"] = tz

    with mock.patch.dict(os.environ, env_dict, clear=True):
        # Reconfigure DISPLAY_TZINFO
        flow.record.fieldtypes.DISPLAY_TZINFO = flow_record_tz(default_tz="UTC")

        rdump.main([str(tmp_path / "test.records"), *rdump_params])
        captured = capsys.readouterr()
        assert captured.err == ""
        assert expected_date_str in captured.out

    # restore DISPLAY_TZINFO just in case
    flow.record.fieldtypes.DISPLAY_TZINFO = flow_record_tz(default_tz="UTC")


def test_flow_record_invalid_tz(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    TestRecord = RecordDescriptor(
        "test/flow_record_tz",
        [
            ("datetime", "stamp"),
        ],
    )
    with RecordWriter(tmp_path / "test.records") as writer:
        writer.write(TestRecord(stamp="2023-08-16T17:46:55.390691+02:00"))

    env_dict = {
        "FLOW_RECORD_TZ": "invalid",
    }

    with mock.patch.dict(os.environ, env_dict, clear=True):
        # Reconfigure DISPLAY_TZINFO
        with pytest.warns(UserWarning, match=".* falling back to timezone.utc"):
            flow.record.fieldtypes.DISPLAY_TZINFO = flow_record_tz()

        rdump.main([str(tmp_path / "test.records")])
        captured = capsys.readouterr()
        assert captured.err == ""
        assert "2023-08-16 15:46:55.390691+00:00" in captured.out
        assert timezone.utc == flow.record.fieldtypes.DISPLAY_TZINFO

    # restore DISPLAY_TZINFO just in case
    flow.record.fieldtypes.DISPLAY_TZINFO = flow_record_tz(default_tz="UTC")


@pytest.mark.parametrize(
    "rdump_params",
    [
        ["--mode=line-verbose"],
        ["--line-verbose"],
        ["-Lv"],
        ["-w", "line://?verbose=true"],
        ["-w", "line://?verbose=1"],
        ["-w", "line://?verbose=True"],
    ],
)
def test_rdump_line_verbose(tmp_path: Path, capsys: pytest.CaptureFixture, rdump_params: list[str]) -> None:
    TestRecord = RecordDescriptor(
        "test/rdump/line_verbose",
        [
            ("datetime", "stamp"),
            ("bytes", "data"),
            ("uint32", "counter"),
            ("string", "foo"),
        ],
    )
    record_path = tmp_path / "test.records"

    with RecordWriter(record_path) as writer:
        writer.write(TestRecord(counter=1))
        writer.write(TestRecord(counter=2))
        writer.write(TestRecord(counter=3))

    field_types_for_record_descriptor.cache_clear()
    assert field_types_for_record_descriptor.cache_info().currsize == 0
    rdump.main([str(record_path), *rdump_params])
    assert field_types_for_record_descriptor.cache_info().misses == 1
    assert field_types_for_record_descriptor.cache_info().hits == 2
    assert field_types_for_record_descriptor.cache_info().currsize == 1

    captured = capsys.readouterr()
    assert captured.err == ""
    assert "stamp (datetime) =" in captured.out
    assert "data (bytes) =" in captured.out
    assert "counter (uint32) =" in captured.out
    assert "foo (string) =" in captured.out


def test_rdump_list_progress(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    TestRecord = RecordDescriptor(
        "test/rdump/progress",
        [
            ("uint32", "counter"),
        ],
    )
    record_path = tmp_path / "test.records"

    with RecordWriter(record_path) as writer:
        for i in range(100):
            writer.write(TestRecord(counter=i))

    rdump.main(["--list", "--progress", str(record_path)])
    captured = capsys.readouterr()

    # stderr should contain tqdm progress bar
    #   100 records [00:00, 64987.67 records/s]
    assert "\r100 records [" in captured.err
    assert " records/s]" in captured.err

    # stdout should contain the RecordDescriptor definition and count
    assert "# <RecordDescriptor test/rdump/progress, hash=eeb21156>" in captured.out
    assert "Processed 100 records" in captured.out
