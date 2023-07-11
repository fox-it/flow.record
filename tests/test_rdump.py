import base64
import hashlib
import json
import os
import platform
import subprocess

import pytest

from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.tools import rdump


def test_rdump_pipe(tmp_path):
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
    assert b"Unknown file format, not a RecordStream" in stderr.strip()

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


def test_rdump_format_template(tmp_path):
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
        assert line == "TEST: {i},bar".format(i=i)


def test_rdump_json(tmp_path):
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
                ip="172.16.0.{}".format(i),
                subnet="192.168.{}.0/24".format(i),
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
        assert base64.b64encode("\x00\x01\x02\x03--{}".format(i).encode()) in stdout
        assert "192.168.{}.0/24".format(i).encode() in stdout
        assert "172.16.0.{}".format(i).encode() in stdout
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
            assert json_dict["data"] == base64.b64encode("\x00\x01\x02\x03--{}".format(count).encode()).decode()
            assert json_dict["ip"] == "172.16.0.{}".format(count)
            assert json_dict["subnet"] == "192.168.{}.0/24".format(count)
            assert json_dict["digest"]["md5"] == md5
            assert json_dict["digest"]["sha1"] == sha1
            assert json_dict["digest"]["sha256"] == sha256

    # Write jsonlines to file
    path = tmp_path / "records.jsonl"
    path.write_bytes(stdout)
    json_path = "jsonfile://{}".format(path)

    # Read records from json and original records file and validate
    for path in (json_path, record_path):
        with RecordReader(path) as reader:
            for i, record in enumerate(reader):
                data = str(i).encode()
                md5 = hashlib.md5(data).hexdigest()
                sha1 = hashlib.sha1(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                assert record.count == i
                assert record.ip == "172.16.0.{}".format(i)
                assert record.subnet == "192.168.{}.0/24".format(i)
                assert record.data == b"\x00\x01\x02\x03--" + data
                assert record.digest.md5 == md5
                assert record.digest.sha1 == sha1
                assert record.digest.sha256 == sha256
                assert record.foo == "bar" * i


def test_rdump_json_no_descriptors(tmp_path):
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


def test_rdump_format_spec_hex(tmp_path):
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


def test_rdump_list_adapters():
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
def test_rdump_split(tmp_path, filename):
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


def test_rdump_split_suffix_length(tmp_path):
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
    "scheme,first_line",
    [
        ("csvfile://", b"count,"),
        ("jsonfile://", b"recorddescriptor"),
        ("jsonfile://?descriptors=false", b"X-TEST-"),
        ("text://", b"<test/record"),
    ],
)
def test_rdump_split_using_uri(tmp_path, scheme, first_line, capsysbinary):
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
        with open(path, "rb") as f:
            assert first_line in next(f)


def test_rdump_split_without_writer(capsysbinary):
    with pytest.raises(SystemExit):
        rdump.main(["--split=10"])
    captured = capsysbinary.readouterr()
    assert b"error: --split only makes sense in combination with -w/--writer" in captured.err


def test_rdump_csv(tmp_path, capsysbinary):
    path = tmp_path / "test.csv"
    with open(path, "w") as f:
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


def test_rdump_headerless_csv(tmp_path, capsysbinary):
    # write out headerless CSV file
    path = tmp_path / "test.csv"
    with open(path, "w") as f:
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


@pytest.mark.parametrize(["count", "skip"], [(None, 2), (3, None), (2, 3)])
def test_rdump_count_and_skip(tmp_path, capsysbinary, count, skip):
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "number"),
            ("string", "foo"),
        ],
    )

    # Generate some test records and write them to a file
    NUMBER_OF_TEST_RECORDS = 10
    full_set_path = tmp_path / "test_full_set.records"
    writer = RecordWriter(full_set_path)

    test_records = []
    for i in range(NUMBER_OF_TEST_RECORDS):
        record = TestRecord(number=i, foo="bar" + "baz" * i)
        test_records.append(record)
        writer.write(record)
    writer.close()

    rdump_parameters = []

    # Work out where in the test_records list the first and last record will be once we have skipped and counted
    expected_first_record_index = 0
    expected_last_record_index = NUMBER_OF_TEST_RECORDS - 1
    expected_number_of_records = min(count if count else NUMBER_OF_TEST_RECORDS, NUMBER_OF_TEST_RECORDS)
    if skip and not count:
        # Decrease the expected number of records, because we skipped some while not supplying a max count
        expected_number_of_records -= skip
    if count:
        rdump_parameters.append(f"--count={count}")
        expected_last_record_index = count - 1
    if skip:
        rdump_parameters.append(f"--skip={skip}")
        expected_first_record_index += skip
        expected_last_record_index += skip

    # We expect of rdump that if the count and skip parameters go further than the amount of records that are actually
    # available, rdump will just stop reading/writing.
    expected_last_record_index = min(NUMBER_OF_TEST_RECORDS - 1, expected_last_record_index)

    # Read from the full records file using rdump with the skip and count parameters. We do this to test if rdump
    # filters accordingly.
    rdump_read_parameters = [str(full_set_path)] + rdump_parameters + ["--csv", "-F", "foo"]
    rdump.main(rdump_read_parameters)

    captured = capsysbinary.readouterr()
    assert captured.err == b""

    record_lines = captured.out.splitlines()[1:]

    # Verify we have the amount of records that we expect, and that the first and last record have the correct value.
    assert len(record_lines) == expected_number_of_records
    assert test_records[expected_first_record_index].foo == record_lines[0].decode()
    assert test_records[expected_last_record_index].foo == record_lines[-1].decode()

    # We also want to test if skip and count work correctly when writing records. Rdump should read the full recordfile,
    # and then correctly write a subset (using count and skip) to the subset file
    subset_path = tmp_path / "test_subset.records"
    rdump.main([str(full_set_path), "-w"] + [str(subset_path)] + rdump_parameters)

    # Now we read the subsetted recordfile in its entirety, and check if the skip and count parameters were interpreted
    # correctly.
    rdump.main([str(subset_path), "--csv", "-F", "foo"])

    captured = capsysbinary.readouterr()
    assert captured.err == b""

    record_lines = captured.out.splitlines()[1:]
    assert len(record_lines) == expected_number_of_records
    assert test_records[expected_first_record_index].foo == record_lines[0].decode()
    assert test_records[expected_last_record_index].foo == record_lines[-1].decode()
