import sys
import pytest
from flow.record import RECORD_VERSION
from flow.record import RecordDescriptor, RecordDescriptorError
from flow.record import RecordPacker
from flow.record import RecordWriter, RecordReader, RecordPrinter
from flow.record import Record, GroupedRecord
from flow.record import record_stream, extend_record
from flow.record import fieldtypes
from flow.record.stream import RecordFieldRewriter

from . import utils_inspect as inspect


def test_record_creation():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
        ],
    )

    # No arguments defaults to None
    r = TestRecord()
    assert r.url is None
    assert r.query is None

    # Keyword arguments
    r = TestRecord(url="foo", query="bar")
    assert r.url == "foo"
    assert r.query == "bar"

    # Positional arguments
    r = TestRecord("foo", "bar")
    assert r.url == "foo"
    assert r.query == "bar"

    # Single keyword argument
    r = TestRecord(query="foo")
    assert r.query == "foo"
    assert r.url is None


def test_record_version(tmpdir):
    path = "jsonfile://{}".format(tmpdir.join("test.jsonl").strpath)
    writer = RecordWriter(path)
    packer = RecordPacker()
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "hello"),
            ("string", "world"),
        ],
    )

    r1 = TestRecord(hello="hello", world="world")
    writer.write(r1)
    data = packer.pack(r1)
    u1 = packer.unpack(data)
    print(repr(u1._desc))

    assert u1.hello == r1.hello
    assert u1.world == r1.world

    # change the order
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "world"),
            ("string", "hello"),
        ],
    )
    r2 = TestRecord(hello="hello", world="world")
    writer.write(r2)
    data = packer.pack(r2)
    u2 = packer.unpack(data)

    assert u2.hello == r2.hello
    assert u2.world == r2.world
    print(repr(u2._desc))

    # change fieldtypes
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "world"),
            ("string", "hello"),
        ],
    )
    r3 = TestRecord(hello="hello", world=42)
    writer.write(r3)
    data = packer.pack(r3)
    u3 = packer.unpack(data)

    writer.flush()

    assert u3._desc.identifier == r3._desc.identifier
    assert u1._desc.identifier != u3._desc.identifier
    assert u2._desc.identifier != u3._desc.identifier
    assert u3.hello == r3.hello
    assert u3.world == r3.world

    reader = RecordReader(path)
    rec = [r for r in reader]
    assert len(rec) == 3
    assert u3._desc.identifier == rec[2]._desc.identifier
    assert u1._desc.identifier != rec[2]._desc.identifier
    assert u2._desc.identifier != rec[2]._desc.identifier
    assert u3.hello == rec[2].hello
    assert u3.world == rec[2].world


def test_grouped_record():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "hello"),
            ("string", "world"),
            ("uint32", "count"),
        ],
    )
    WQMetaRecord = RecordDescriptor(
        "wq/meta",
        [
            ("string", "assignee"),
            ("string", "profile"),
            ("string", "hello"),
        ],
    )

    test_record = TestRecord("a", "b", 12345)
    meta_record = WQMetaRecord("me", "this is a test", "other hello")

    grouped = GroupedRecord("grouped/wq", [test_record, meta_record])
    assert grouped.hello == "a"
    assert grouped.world == "b"
    assert grouped.count == 12345
    assert grouped.assignee == "me"
    assert grouped.profile == "this is a test"

    grouped.profile = "omg"
    grouped.hello = "new value"
    assert grouped.hello == "new value"
    assert grouped.profile == "omg"
    assert grouped.records[0].hello == "new value"
    assert grouped.records[1].hello == "other hello"

    grouped.records[1].hello = "testing"
    assert grouped.hello != "testing"
    assert grouped.hello == "new value"
    assert grouped.records[1].hello == "testing"

    assert len(grouped.records) == 2

    # test grouped._asdict
    rdict = grouped._asdict()
    assert set(["hello", "world", "count", "assignee", "profile", "hello"]) <= set(rdict)

    rdict = grouped._asdict(fields=["profile", "count", "_generated"])
    assert set(["profile", "count", "_generated"]) == set(rdict)
    assert rdict["profile"] == "omg"
    assert rdict["count"] == 12345


def test_grouped_records_packing(tmpdir):
    RecordA = RecordDescriptor(
        "test/a",
        [
            ("string", "a_string"),
            ("string", "common"),
            ("uint32", "a_count"),
        ],
    )
    RecordB = RecordDescriptor(
        "test/b",
        [
            ("string", "b_string"),
            ("string", "common"),
            ("uint32", "b_count"),
        ],
    )
    a = RecordA("hello", "world", 12345, _source="TheBadInternet", _classification="CLASSIFIED")
    b = RecordB("good", "bye", 54321, _source="TheGoodInternet", _classification="TLP.WHITE")
    assert isinstance(a, Record)
    assert not isinstance(a, GroupedRecord)

    grouped = GroupedRecord("grouped/ab", [a, b])
    assert isinstance(grouped, (Record, GroupedRecord))
    assert [(f.typename, f.name) for f in grouped._desc.fields.values()] == [
        ("string", "a_string"),
        ("string", "common"),
        ("uint32", "a_count"),
        ("string", "b_string"),
        ("uint32", "b_count"),
    ]

    path = tmpdir.join("grouped.records").strpath
    writer = RecordWriter(path)
    writer.write(grouped)
    writer.write(grouped)
    writer.write(grouped)
    writer.write(grouped)
    writer.write(grouped)
    writer.flush()

    reader = RecordReader(path)
    record = next(iter(reader))

    # grouped record tests
    assert isinstance(record, Record)
    assert isinstance(record, GroupedRecord)
    assert record.common == "world"  # first 'key' has precendence
    assert record.name == "grouped/ab"
    assert record.a_string == "hello"
    assert record.a_count == 12345
    assert record.b_count == 54321
    assert record.b_string == "good"
    assert record._source == "TheBadInternet"
    assert record._classification == "CLASSIFIED"

    # access 'common' on second record directly
    assert record.records[1].common == "bye"

    # access raw records directly
    assert len(record.records) == 2
    assert record.records[0]._desc.name == "test/a"
    assert record.records[1]._desc.name == "test/b"

    # test using selectors
    reader = RecordReader(path, selector="r.a_count == 12345")
    assert len(list(iter(reader))) == 5

    reader = RecordReader(path, selector="r.common == 'bye'")
    assert len(list(iter(reader))) == 0
    reader = RecordReader(path, selector="r.common == 'world'")
    assert len(list(iter(reader))) == 5


def test_record_reserved_fieldname():
    with pytest.raises(RecordDescriptorError):
        RecordDescriptor(
            "test/a",
            [
                ("string", "_classification"),
                ("string", "_source"),
                ("uint32", "_generated"),
            ],
        )


def test_record_printer_stdout(capsys):
    Record = RecordDescriptor(
        "test/a",
        [
            ("string", "a_string"),
            ("string", "common"),
            ("uint32", "a_count"),
        ],
    )
    record = Record("hello", "world", 10)

    # fake capsys to be a tty.
    def isatty():
        return True

    capsys._capture.out.tmpfile.isatty = isatty

    writer = RecordPrinter(getattr(sys.stdout, "buffer", sys.stdout))
    writer.write(record)

    out, err = capsys.readouterr()
    modifier = "" if isinstance("", str) else "u"
    expected = "<test/a a_string={u}'hello' common={u}'world' a_count=10>\n".format(u=modifier)
    assert out == expected


def test_record_field_limit():
    count = 1337
    fields = [("uint32", "field_{}".format(i)) for i in range(count)]
    values = dict([("field_{}".format(i), i) for i in range(count)])

    Record = RecordDescriptor("test/limit", fields)
    record = Record(**values)

    for i in range(count):
        assert getattr(record, "field_{}".format(i)) == i

    # test kwarg init
    record = Record(field_404=12345)
    assert record.field_404 == 12345
    assert record.field_0 is None

    # test arg init
    record = Record(200, 302, 404)
    assert record.field_0 == 200
    assert record.field_1 == 302
    assert record.field_2 == 404
    assert record.field_404 is None

    # test arg + kwarg init
    record = Record(200, 302, 404, field_502=502)
    assert record.field_0 == 200
    assert record.field_1 == 302
    assert record.field_2 == 404
    assert record.field_3 is None
    assert record.field_502 == 502


def test_record_internal_version():
    Record = RecordDescriptor(
        "test/a",
        [
            ("string", "a_string"),
            ("string", "common"),
            ("uint32", "a_count"),
        ],
    )

    record = Record("hello", "world", 10)
    assert record._version == RECORD_VERSION

    record = Record("hello", "world", 10, _version=1337)
    assert record._version == RECORD_VERSION


def test_record_reserved_keyword():
    Record = RecordDescriptor(
        "test/a",
        [
            ("string", "from"),
            ("string", "and"),
            ("uint32", "or"),
            ("uint32", "normal"),
        ],
    )

    init = Record.recordType.__init__
    sig = inspect.signature(init)
    params = list(sig.parameters.values())
    assert init.__code__.co_argcount == 1
    assert len(params) == 3
    assert params[1].name == "args"
    assert params[1].kind == params[1].VAR_POSITIONAL
    assert params[2].name == "kwargs"
    assert params[2].kind == params[2].VAR_KEYWORD

    r = Record("hello", "world", 1337, 10)
    assert getattr(r, "from") == "hello"
    assert getattr(r, "and") == "world"
    assert getattr(r, "or") == 1337
    assert r.normal == 10

    r = Record("some", "missing", normal=5)
    assert getattr(r, "from") == "some"
    assert getattr(r, "and") == "missing"
    assert getattr(r, "or") is None
    assert r.normal == 5

    r = Record("from_value", **{"and": "dict", "or": 7331, "normal": 3})
    assert getattr(r, "from") == "from_value"
    assert getattr(r, "and") == "dict"
    assert getattr(r, "or") == 7331
    assert r.normal == 3

    Record = RecordDescriptor(
        "test/a",
        [
            ("uint32", "normal"),
        ],
    )

    init = Record.recordType.__init__
    sig = inspect.signature(init)
    params = list(sig.parameters.values())
    assert init.__code__.co_argcount == 6
    assert len(params) == 6
    assert params[1].name == "normal"
    assert params[1].kind == params[1].POSITIONAL_OR_KEYWORD
    assert params[1].default is None
    assert params[2].name == "_source"
    assert params[2].kind == params[2].POSITIONAL_OR_KEYWORD
    assert params[2].default is None
    assert params[3].name == "_classification"
    assert params[3].kind == params[3].POSITIONAL_OR_KEYWORD
    assert params[3].default is None
    assert params[4].name == "_generated"
    assert params[4].kind == params[4].POSITIONAL_OR_KEYWORD
    assert params[4].default is None
    assert params[5].name == "_version"
    assert params[5].kind == params[5].POSITIONAL_OR_KEYWORD
    assert params[5].default is None

    Record = RecordDescriptor(
        "test/a",
        [
            ("uint32", "self"),
            ("uint32", "cls"),
        ],
    )
    r = Record(1, 2)
    assert r.self == 1
    assert r.cls == 2


def test_record_stream(tmp_path):
    Record = RecordDescriptor(
        "test/counter",
        [
            ("uint32", "counter"),
            ("string", "tag"),
        ],
    )

    datasets = [
        tmp_path / "dataset1.records",
        tmp_path / "dataset2.records.gz",
    ]

    for ds in datasets:
        writer = RecordWriter(str(ds))
        for i in range(100):
            writer.write(Record(i, tag=ds.name))
        writer.close()

    datasets = [str(ds) for ds in datasets]
    assert len(list(record_stream(datasets))) == len(datasets) * 100
    assert len(list(record_stream(datasets, "r.counter == 42"))) == len(datasets)


def test_record_replace():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "index"),
            ("string", "foo"),
        ],
    )

    t = TestRecord(1, "hello")
    assert t.index == 1
    assert t.foo == "hello"

    t2 = t._replace(foo="bar", index=1337)
    assert t2.foo == "bar"
    assert t2.index == 1337

    t3 = t._replace()
    assert t3.index == 1
    assert t3.foo == "hello"
    assert t3._source == t._source
    assert t3._generated == t._generated
    assert t3._version == t._version

    t4 = t2._replace(foo="test", _source="pytest")
    assert t4.index == 1337
    assert t4.foo == "test"
    assert t4._source == "pytest"
    assert t4._generated == t2._generated

    with pytest.raises(ValueError) as excinfo:
        t._replace(foobar="keyword does not exist")
    excinfo.match(".*Got unexpected field names:.*foobar.*")


def test_record_init_from_record():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("uint32", "index"),
            ("string", "foo"),
        ],
    )

    t = TestRecord(1, "hello")
    assert t.index == 1
    assert t.foo == "hello"

    TestRecord2 = TestRecord.extend(
        [
            ("string", "bar"),
            ("uint32", "test"),
        ]
    )
    t2 = TestRecord2.init_from_record(t)
    assert t2.index == 1
    assert t2.foo == "hello"
    assert t2.bar is None
    assert t2.test is None

    t2.bar = "bar"
    t2.test = 3
    assert t2.bar == "bar"
    assert t2.test == 3

    TestRecord3 = RecordDescriptor(
        "test/record3",
        [
            ("string", "test"),
            ("uint32", "count"),
        ],
    )
    with pytest.raises(TypeError):
        t3 = TestRecord3.init_from_record(t2, raise_unknown=True)

    # explicit raise_unknown=False
    t3 = TestRecord3.init_from_record(t2, raise_unknown=False)
    assert t3.test == "3"
    assert t3.count is None

    # default should not raise either
    t3 = TestRecord3.init_from_record(t2)
    assert t3.test == "3"
    assert t3.count is None


def test_record_asdict():
    Record = RecordDescriptor(
        "test/a",
        [
            ("string", "a_string"),
            ("string", "common"),
            ("uint32", "a_count"),
        ],
    )
    record = Record("hello", "world", 1337)
    rdict = record._asdict()
    assert rdict.get("a_string") == "hello"
    assert rdict.get("common") == "world"
    assert rdict.get("a_count") == 1337
    assert set(rdict) == set(["a_string", "common", "a_count", "_source", "_generated", "_version", "_classification"])

    rdict = record._asdict(fields=["common", "_source", "a_string"])
    assert set(rdict) == set(["a_string", "common", "_source"])

    rdict = record._asdict(exclude=["a_count", "_source", "_generated", "_version"])
    assert set(rdict) == set(["a_string", "common", "_classification"])

    rdict = record._asdict(fields=["common", "_source", "a_string"], exclude=["common"])
    assert set(rdict) == set(["a_string", "_source"])


def test_recordfield_rewriter_expression():
    rewriter = RecordFieldRewriter(expression="upper_a = a_string.upper(); count_times_10 = a_count * 10")
    Record = RecordDescriptor(
        "test/a",
        [
            ("string", "a_string"),
            ("string", "common"),
            ("uint32", "a_count"),
        ],
    )
    record = Record("hello", "world", 1337)
    new_record = rewriter.rewrite(record)
    assert new_record.a_string == "hello"
    assert new_record.common == "world"
    assert new_record.a_count == 1337
    assert new_record.upper_a == "HELLO"
    assert new_record.count_times_10 == 1337 * 10


def test_recordfield_rewriter_fields():
    rewriter = RecordFieldRewriter(fields=["a_count"])
    Record = RecordDescriptor(
        "test/a",
        [
            ("string", "a_string"),
            ("string", "common"),
            ("uint32", "a_count"),
        ],
    )
    record = Record("hello", "world", 1337)
    new_record = rewriter.rewrite(record)
    assert hasattr(new_record, "a_count")
    assert not hasattr(new_record, "a_string")
    assert not hasattr(new_record, "common")


def test_extend_record():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
        ],
    )
    FooRecord = RecordDescriptor(
        "test/foo",
        [
            ("varint", "foo"),
            ("bytes", "query"),
            ("bytes", "bar"),
        ],
    )
    HelloRecord = RecordDescriptor(
        "test/hello",
        [
            ("string", "hello"),
            ("string", "world"),
            ("string", "url"),
        ],
    )

    a = TestRecord("http://flow.record", "myquery")
    b = FooRecord(12345, b"FOO", b"BAR")
    c = HelloRecord("hello", "world", "http://hello.world")

    new = extend_record(a, [b, c])
    assert new._desc == RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("string", "query"),
            ("varint", "foo"),
            ("bytes", "bar"),
            ("string", "hello"),
            ("string", "world"),
        ],
    )
    assert new.url == "http://flow.record"
    assert new.query == "myquery"
    assert new.foo == 12345
    assert new.bar == b"BAR"
    assert new.hello == "hello"
    assert new.world == "world"

    new = extend_record(a, [b, c], replace=True)
    assert new._desc == RecordDescriptor(
        "test/record",
        [
            ("string", "url"),
            ("bytes", "query"),
            ("varint", "foo"),
            ("bytes", "bar"),
            ("string", "hello"),
            ("string", "world"),
        ],
    )
    assert new.url == "http://hello.world"
    assert new.query == b"FOO"
    assert new.foo == 12345
    assert new.bar == b"BAR"
    assert new.hello == "hello"
    assert new.world == "world"


def test_extend_record_with_replace():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "ip"),
            ("uint16", "port"),
            ("string", "data"),
            ("string", "note"),
        ],
    )
    ReplaceRecord = RecordDescriptor(
        "test/foo",
        [
            ("net.ipaddress", "ip"),
            ("net.tcp.Port", "port"),
            ("bytes", "data"),
            ("string", "location"),
        ],
    )

    a = TestRecord("10.13.13.17", 80, "HTTP/1.1 200 OK\r\n", "webserver")
    b = ReplaceRecord(
        ip=a.ip,
        port=a.port,
        data=a.data.encode(),
        location="DMZ",
    )
    new = extend_record(a, [b], replace=False)
    assert new.ip == "10.13.13.17"
    assert new.port == 80
    assert new.data == "HTTP/1.1 200 OK\r\n"
    assert new.note == "webserver"
    assert new.location == "DMZ"
    assert isinstance(new.ip, str)
    assert isinstance(new.port, int)
    assert isinstance(new.data, str)
    assert isinstance(new.note, str)
    assert isinstance(new.location, str)
    assert new._desc.name == "test/record"
    assert "<test/record " in repr(new)

    new = extend_record(a, [b], replace=True, name="test/replaced")
    assert new.ip == "10.13.13.17"
    assert new.port == 80
    assert new.data == b"HTTP/1.1 200 OK\r\n"
    assert new.note == "webserver"
    assert new.location == "DMZ"
    assert isinstance(new.ip, fieldtypes.net.ipaddress)
    assert isinstance(new.port, fieldtypes.net.tcp.Port)
    assert isinstance(new.data, bytes)
    assert isinstance(new.note, str)
    assert isinstance(new.location, str)
    assert new._desc.name == "test/replaced"
    assert "<test/replaced " in repr(new)
