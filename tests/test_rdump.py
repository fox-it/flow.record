import json
import base64
import hashlib
import subprocess

from flow.record import RecordDescriptor
from flow.record import RecordWriter, RecordReader


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
    p2 = subprocess.Popen(["wc", "-l"], stdin=p1.stdout, stdout=subprocess.PIPE)
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
