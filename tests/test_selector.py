from __future__ import annotations

from datetime import datetime, timezone

import pytest

from flow.record import RecordDescriptor
from flow.record.selector import CompiledSelector, InvalidOperation, Selector


def test_selector_func_name() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )
    assert TestRecord(None, None) not in Selector("name(r) == 'foo/bar'")
    assert TestRecord(None, None) in Selector("name(r) == 'test/record'")


def test_selector() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )
    TestRecord2 = RecordDescriptor(
        "test/record2",
        [
            ("string", "key"),
            ("string", "content"),
        ],
    )

    assert TestRecord("foo", "bar") in Selector("r.query == 'foo'")
    assert TestRecord(None, None) not in Selector("r.query == 'foo'")
    assert TestRecord(None, None) not in Selector("name(r.query) == 'XX'")

    with pytest.raises(InvalidOperation):
        assert TestRecord(None, None) not in Selector("r.__class__ == 'str'")

    s = Selector("lower(upper(r.content)) == 'xx'")
    assert TestRecord("XX", "XX") not in s
    assert TestRecord2("XX", "XX") in s

    assert TestRecord(None, "BAR") in Selector(
        "lower(r.query) == 'test' or lower(r.adsadsa) == 't' or lower(r.url) == 'bar'"
    )

    with pytest.raises(InvalidOperation):
        assert TestRecord() in Selector("invalid_func(r.invalid_field, 1337) or r.id == 4")


def test_selector_str_repr() -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )

    assert TestRecord("foo", "bar") in Selector("'foo' in str(r)")
    assert TestRecord("foo", "bar") in Selector("'test/record' in str(r)")
    assert TestRecord("foo", "bar") in Selector("'foo' in repr(r)")
    assert TestRecord("foo", "bar") in Selector("'test/record' in repr(r)")
    assert TestRecord("foo", "bar") in CompiledSelector("'foo' in str(r)")
    assert TestRecord("foo", "bar") in CompiledSelector("'test/record' in str(r)")
    assert TestRecord("foo", "bar") in CompiledSelector("'foo' in repr(r)")
    assert TestRecord("foo", "bar") in CompiledSelector("'test/record' in repr(r)")

    assert TestRecord("foo", "bar") not in Selector("'nope' in str(r)")
    assert TestRecord("foo", "bar") not in Selector("'nope' in repr(r)")
    assert TestRecord("foo", "bar") not in CompiledSelector("'nope' in str(r)")
    assert TestRecord("foo", "bar") not in CompiledSelector("'nope' in repr(r)")


def test_selector_meta_query_true() -> None:
    source = "internal/flow.record.test"

    desc = RecordDescriptor(
        "test/record",
        [
            ("string", "value"),
        ],
    )
    rec = desc("value", _source=source)
    assert rec in Selector(f"r._source == '{source}'")


def test_selector_meta_query_false() -> None:
    source = "internal/flow.record.test"

    desc = RecordDescriptor(
        "test/record",
        [
            ("string", "value"),
        ],
    )
    rec = desc("value", _source=source + "nope")
    assert (rec in Selector(f"r._source == '{source}'")) is False


def test_selector_basic_query_true() -> None:
    md5hash = "My MD5 hash!"

    desc = RecordDescriptor(
        "test/md5_hash",
        [
            ("string", "md5"),
        ],
    )
    rec = desc(md5hash)
    assert rec in Selector(f"r.md5 == '{md5hash}'")


def test_selector_basic_query_false() -> None:
    md5hash = "My MD5 hash!"

    desc = RecordDescriptor(
        "test/md5_hash",
        [
            ("string", "md5"),
        ],
    )
    rec = desc(md5hash + "nope")
    assert (rec in Selector(f"r.md5 == '{md5hash}'")) is False


def test_selector_non_existing_field() -> None:
    md5hash = "My MD5 hash!"

    desc = RecordDescriptor(
        "test/md5_hash",
        [
            ("string", "md5"),
        ],
    )
    rec = desc(md5hash)
    assert (rec in Selector("r.non_existing_field == 1337")) is False


# [MS] Disabled, list types?
# def test_selector_string_in_array():
#    obj = Expando()
#    obj.filenames = ['record_mitchel_keystrokes.exe', 'python.exe', 'chrome.exe']

#    s = Selector("'{}' in r.filenames".format(obj.filenames[0]))
#    assert (obj in s) is True


def test_selector_string_contains() -> None:
    desc = RecordDescriptor(
        "test/filetype",
        [
            ("string", "filetype"),
        ],
    )
    rec = desc("PE32 executable (GUI) Intel 80386, for MS Windows")

    assert rec in Selector("'PE' in r.filetype")


def test_selector_not_in_operator() -> None:
    desc = RecordDescriptor(
        "test/md5_hash",
        [
            ("string", "filetype"),
        ],
    )
    rec = desc("PE32 executable (GUI) Intel 80386, for MS Windows")

    assert rec in Selector("'ELF' not in r.filetype")


def test_selector_or_operator() -> None:
    desc = RecordDescriptor(
        "test/filetype",
        [
            ("string", "filetype"),
        ],
    )
    rec = desc("PE32 executable (GUI) Intel 80386, for MS Windows")

    assert rec in Selector("'PE32' in r.filetype or 'PE64' in r.xxxx")


def test_selector_and_operator() -> None:
    desc = RecordDescriptor(
        "test/filetype",
        [
            ("string", "filetype"),
            ("string", "xxxx"),
        ],
    )

    rec = desc("PE32 executable (GUI) Intel 80386, for MS Windows", "PE32 executable (GUI) Intel 80386, for MS Windows")

    assert rec in Selector("'PE32' in r.filetype and 'PE32' in r.xxxx")


def test_selector_in_function() -> None:
    desc = RecordDescriptor(
        "test/filetype",
        [
            ("string", "filetype"),
        ],
    )
    rec = desc("PE32 executable (GUI) Intel 80386, for MS Windows")

    assert rec in Selector("'pe' in lower(r.filetype)")


def test_selector_function_call_whitelisting() -> None:
    TestRecord = RecordDescriptor(
        "test/filetype",
        [
            ("string", "filetype"),
        ],
    )
    rec = TestRecord("PE32 executable (GUI) Intel 80386, for MS Windows")

    # We allow explicitly exposed functions
    assert rec in Selector("'pe32' in lower(r.filetype)")
    # But functions on types are not
    with pytest.raises(
        Exception, match="Call 'r.filetype.lower' not allowed. No calls other then whitelisted 'global' calls allowed!"
    ):
        assert rec in Selector("'pe' in r.filetype.lower()")

    assert rec in Selector("'EXECUTABLE' in upper(r.filetype)")
    with pytest.raises(
        Exception, match="Call 'r.filetype.upper' not allowed. No calls other then whitelisted 'global' calls allowed!"
    ):
        assert rec in Selector("'EXECUTABLE' in r.filetype.upper()")

    IPRecord = RecordDescriptor(
        "test/address",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )
    with pytest.deprecated_call():
        rec = IPRecord("192.168.1.1")
        assert rec in Selector("r.ip in net.ipv4.Subnet('192.168.1.0/24')")
        assert rec not in Selector("r.non_existing_field in net.ipv4.Subnet('192.168.1.0/24')")

    # We call net.ipv4 instead of net.ipv4.Subnet, which should fail
    with pytest.raises(
        Exception, match="Call 'net.ipv4' not allowed. No calls other then whitelisted 'global' calls allowed!"
    ):
        assert rec in Selector("r.ip in net.ipv4('192.168.1.0/24')")


def test_selector_subnet() -> None:
    desc = RecordDescriptor(
        "test/ip",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )
    with pytest.deprecated_call():
        rec = desc("192.168.10.1")

        assert rec in Selector("r.ip in net.ipv4.Subnet('192.168.10.1/32')")
        assert rec in Selector("r.ip in net.ipv4.Subnet('192.168.10.0/24')")
        assert rec in Selector("r.ip in net.ipv4.Subnet('192.168.0.0/16')")
        assert rec in Selector("r.ip in net.ipv4.Subnet('192.0.0.0/8')")
        assert rec in Selector("r.ip in net.ipv4.Subnet('192.168.10.1')")
        assert rec in Selector("r.ip not in net.ipv4.Subnet('10.0.0.0/8')")


def test_field_equals() -> None:
    desc = RecordDescriptor(
        "test/record",
        [
            ("string", "mailfrom"),
            ("string", "mailto"),
            ("string", "foo"),
        ],
    )
    rec = desc("hello@world.com", "foo@bar.com", "testing")
    assert rec in CompiledSelector("field_equals(r, ['mailfrom', 'mailto'], ['hello@world.com',])")
    assert rec in CompiledSelector("field_equals(r, ['mailfrom', 'mailto'], ['hElLo@WoRlD.com',])")
    assert rec not in CompiledSelector("field_equals(r, ['mailfrom', 'mailto'], ['hElLo@WoRlD.com',], nocase=False)")
    assert rec not in CompiledSelector("field_equals(r, ['mailfrom', 'mailto'], ['hello',])")


def test_field_contains() -> None:
    desc = RecordDescriptor(
        "test/record",
        [
            ("string", "mailfrom"),
            ("string", "mailto"),
            ("string", "foo"),
        ],
    )
    rec = desc("hello@world.com", "foo@bar.com", "testing")
    rec2 = desc("hello@world.com", "foo@bar.com")

    assert rec in CompiledSelector("field_contains(r, ['mailfrom', 'mailto'], ['foo@bar.com', 'test@fox-it.com'])")
    assert rec in CompiledSelector("field_contains(r, ['mailfrom', 'mailto'], ['FOO', 'HELLO'])")
    assert rec in Selector("field_contains(r, ['mailfrom', 'mailto'], ['FOO', 'HELLO'])")
    assert rec2 not in CompiledSelector("field_contains(r, ['testing'], ['TEST@fox-it.com'])")


def test_field_contains_word_boundary() -> None:
    desc = RecordDescriptor(
        "test/record",
        [
            ("string", "mailfrom"),
            ("string", "mailto"),
            ("string", "foo"),
            ("string", "content"),
        ],
    )
    rec = desc("hello@world.com", "foo@bar.com", "testing", "This is a testing string")
    rec2 = desc("helloworld@world.com", "foo@bar.com")
    rec3 = desc(None, None)
    rec4 = desc(None, None, "hello@world.com")
    rec5 = desc()
    assert rec in Selector("field_contains(r, ['mailfrom', 'mailto'], ['hello'], word_boundary=True)")
    assert rec not in Selector(
        "field_contains(r, ['mailfrom', 'mailto'], ['hello.'], word_boundary=True)"
    )  # Check regex escaping...
    assert rec not in Selector("field_contains(r, ['mailfrom', 'mailto'], ['HELLO'], nocase=False, word_boundary=True)")
    assert rec2 not in Selector("field_contains(r, ['mailfrom', 'mailto'], ['hello'], word_boundary=True)")
    assert rec2 not in Selector(
        "field_contains(r, ['mailfrom', 'mailto', 'nonexistingfield'], ['hello'], word_boundary=True)"
    )
    assert rec3 not in Selector("field_contains(r, ['mailfrom', 'mailto'], ['hello'], word_boundary=True)")
    assert rec4 in Selector("field_contains(r, ['mailfrom', 'mailto', 'foo'], ['hello'], word_boundary=True)")
    assert rec5 not in Selector("field_contains(r, ['mailfrom', 'mailto', 'foo'], ['hello'], word_boundary=True)")

    assert rec not in Selector("field_contains(r, ['content'], ['sting'], word_boundary=True)")
    assert rec in Selector("field_contains(r, ['content'], ['testing'], word_boundary=True)")


def test_field_regex() -> None:
    desc = RecordDescriptor(
        "test/record",
        [
            ("string", "mailfrom"),
            ("string", "mailto"),
            ("string", "foo"),
        ],
    )
    rec = desc("hello@world.com", "foo@bar.com", "testing")

    assert rec in Selector(r"field_regex(r, ['mailfrom', 'mailto'], r'.+@.+\.com')")
    assert rec in CompiledSelector(r"field_regex(r, ['mailfrom', 'mailto'], r'.+@.+\.com')")
    assert rec not in Selector("field_regex(r, ['mailfrom', 'mailto'], r'.+@fox-it.com')")
    assert rec not in CompiledSelector("field_regex(r, ['mailfrom', 'mailto'], r'.+@fox-it.com')")


def test_selector_uri() -> None:
    TestRecord = RecordDescriptor(
        "test/uri",
        [
            ("uri", "uri"),
        ],
    )
    rec = TestRecord("http://www.google.com/evil.bin")
    assert rec in Selector("r.uri.filename in ['evil.bin', 'foo.bar']")


def test_selector_typed() -> None:
    TestRecord = RecordDescriptor(
        "test/uri_typed",
        [
            ("uri", "urifield1"),
            ("uri", "urifield2"),
            ("string", "stringfield"),
        ],
    )
    rec = TestRecord("helloworld.exe", "another.bin", "Fox-IT")
    assert rec in Selector("Type.uri.filename == 'helloworld.exe'")
    assert rec in CompiledSelector("Type.uri.filename == 'helloworld.exe'")
    assert rec in Selector("Type.uri.filename != 'howdyworld.exe'")
    assert rec in CompiledSelector("Type.uri.filename != 'howdyworld.exe'")
    assert rec in Selector("'another' in Type.uri.filename")
    assert rec in CompiledSelector("'another' in Type.uri.filename")
    assert rec in Selector("field_contains(r, Type.uri.filename, ['hello'])")
    assert rec in CompiledSelector("field_contains(r, Type.uri.filename, ['hello'])")
    assert rec in Selector("field_equals(r, Type.uri.filename, ['another.bin'])")
    assert rec in CompiledSelector("field_equals(r, Type.uri.filename, ['another.bin'])")
    assert rec in Selector(r"field_regex(r, Type.uri.filename, r'hello\w{5}.exe')")
    assert rec in CompiledSelector(r"field_regex(r, Type.uri.filename, r'hello\w{5}.exe')")

    # Test TypeMatcher reuse
    assert rec in Selector("Type.uri.filename == 'helloworld.exe' or Type.uri.filename == 'another.bin'")
    assert rec in CompiledSelector("Type.uri.filename == 'helloworld.exe' or Type.uri.filename == 'another.bin'")

    assert rec in Selector("Type.string == 'Fox-IT'")
    assert rec in CompiledSelector("Type.string == 'Fox-IT'")
    assert rec in Selector("field_equals(r, Type.string, ['Fox-IT'])")
    assert rec in CompiledSelector("field_equals(r, Type.string, ['Fox-IT'])")
    assert rec in Selector("field_contains(r, Type.string, ['Fox'])")
    assert rec in CompiledSelector("field_contains(r, Type.string, ['Fox'])")
    assert rec in Selector(r"field_regex(r, Type.string, r'Fox-\w{2}')")
    assert rec in CompiledSelector(r"field_regex(r, Type.string, r'Fox-\w{2}')")

    assert rec not in Selector("Type.filename == 'lalala'")
    assert rec not in CompiledSelector("Type.filename == 'lalala'")
    assert rec not in Selector("Type.uri.filename == 'lalala'")
    assert rec not in CompiledSelector("Type.uri.filename == 'lalala'")
    assert rec not in Selector("field_contains(r, Type.uri.filename, ['nope'])")
    assert rec not in CompiledSelector("field_contains(r, Type.uri.filename, ['nope'])")
    assert rec not in Selector("field_equals(r, Type.uri.filename, ['nope'])")
    assert rec not in CompiledSelector("field_equals(r, Type.uri.filename, ['nope'])")
    assert rec not in Selector("field_regex(r, Type.uri.filename, 'nope')")
    assert rec not in CompiledSelector("field_regex(r, Type.uri.filename, 'nope')")

    TestNamespaceRecord = RecordDescriptor(
        "test/ip",
        [
            ("net.ipv4.Address", "ip"),
        ],
    )
    with pytest.deprecated_call():
        rec = TestNamespaceRecord("192.168.10.1")

        # This will only work in "normal" selectors, because we need to override the behaviour
        # of the __contains__ operator to unwrap the requested values
        assert rec in Selector("Type.net.ipv4.Address in net.ipv4.Subnet('192.168.10.1/32')")
        assert rec in Selector("Type.net.ipv4.Address in net.ipv4.Subnet('192.168.10.0/24')")
        assert rec in Selector("Type.net.ipv4.Address in net.ipv4.Subnet('192.168.0.0/16')")
        assert rec in Selector("Type.net.ipv4.Address in net.ipv4.Subnet('192.0.0.0/8')")
        assert rec in Selector("Type.net.ipv4.Address in net.ipv4.Subnet('192.168.10.1')")
        assert rec in Selector("Type.net.ipv4.Address not in net.ipv4.Subnet('10.0.0.0/8')")

    with pytest.raises(InvalidOperation):
        assert rec in Selector("Type.uri.filename.__class__ == 'invalid'")


def test_selector_unicode() -> None:
    TestRecord = RecordDescriptor(
        "test/string",
        [
            ("string", "name"),
        ],
    )
    rec = TestRecord("Jack O'Neill")
    assert rec not in Selector("field_contains(r, ['name'], [u'Jack O\u2019Neill'])")

    rec = TestRecord("jack o\u2019neill")
    assert rec in Selector("field_contains(r, ['name'], [u'Jack O\u2019Neill'])")


def test_record_in_records() -> None:
    RecordA = RecordDescriptor(
        "test/record_a",
        [
            ("datetime", "some_dt"),
            ("string", "field"),
        ],
    )
    RecordB = RecordDescriptor(
        "test/record_b",
        [
            ("record", "record"),
            ("datetime", "some_dt"),
        ],
    )
    RecordC = RecordDescriptor(
        "test/record_c",
        [
            ("record[]", "records"),
        ],
    )
    RecordD = RecordDescriptor(
        "test/record_d",
        [
            ("string[]", "stringlist"),
        ],
    )

    test_str = "this is a test"
    dt = datetime.now(timezone.utc)
    record_a = RecordA(some_dt=dt, field=test_str)
    record_b = RecordB(record=record_a, some_dt=dt)

    subrecords = []
    record_d = None
    for i in range(10):
        record_d = RecordD(stringlist=["aap", "noot", "mies", f"Subrecord {i}"])
        subrecords.append(record_d)

    subrecords.append(record_a)
    record_c = RecordC(records=subrecords)

    subrecords.append(None)
    record_c_with_none_values = RecordC(records=subrecords)

    assert record_b in Selector(f"r.record.field == '{test_str}'")
    assert record_b in Selector(f"Type.string == '{test_str}'")
    assert record_c in Selector(f"Type.string == '{test_str}'")
    assert record_d in Selector("any(s == 'Subrecord 9' for s in r.stringlist)")
    assert record_c in Selector("any(s == 'Subrecord 9' for e in r.records for s in e.stringlist)")
    assert record_c_with_none_values in Selector("any(s == 'Subrecord 9' for e in r.records for s in e.stringlist)")
    assert record_d not in Selector("any(s == 'Subrecord 9' for s in r.nonexistingfield)")


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_non_existing_field(PSelector: type[Selector | CompiledSelector]) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )

    assert TestRecord("foo", "bar") not in PSelector("r.query and r.non_existing_field")
    assert TestRecord("foo", "bar") in PSelector("not r.non_existing_field")
    assert TestRecord("foo", "bar") in PSelector("r.query and r.url and not r.non_existing_field")


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_modulo(PSelector: type[Selector | CompiledSelector]) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "counter"),
        ],
    )

    records = [TestRecord(i) for i in range(300)]

    selected = [rec for rec in records if rec in PSelector("r.counter % 10 == 0")]
    assert len(selected) == 30

    for rec in records:
        sel = PSelector("r.counter % 10 == 0")
        if rec.counter % 10 == 0:
            assert rec in sel
        else:
            assert rec not in sel


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_bit_and(PSelector: type[Selector | CompiledSelector]) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "counter"),
        ],
    )

    records = [TestRecord(i) for i in range(300)]

    for rec in records:
        sel = PSelector("(r.counter & 0x0F) == 1")
        if rec.counter & 0x0F == 1:
            assert rec in sel
        else:
            assert rec not in sel


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_bit_or(PSelector: type[Selector | CompiledSelector]) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "counter"),
        ],
    )

    records = [TestRecord(i) for i in range(300)]

    for rec in records:
        sel = PSelector("(r.counter | 0x10) == 0x11")
        if rec.counter | 0x10 == 0x11:
            assert rec in sel
        else:
            assert rec not in sel


@pytest.mark.parametrize("PSelector", [Selector, CompiledSelector])
def test_selector_modulo_non_existing_field(PSelector: type[Selector | CompiledSelector]) -> None:
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("varint", "counter"),
        ],
    )

    records = [TestRecord(i) for i in range(300)]

    sel = PSelector("r.counter % 10 == 0")
    for rec in records:
        if rec.counter % 10 == 0:
            assert rec in sel
        else:
            assert rec not in sel

    # Test with non existing fields
    # using has_field() ensures that this works with CompiledSelector and Selector
    sel = PSelector("has_field(r, 'counterz') and r.counterz % 10 == 0")
    for rec in records:
        if hasattr(rec, "counterz") and rec.counterz % 10 == 0:
            assert rec in sel
        else:
            assert rec not in sel

    # non existing field but without the precheck (this does not work with CompiledSelector)
    if isinstance(PSelector, Selector):
        sel = PSelector("r.counterz % 10 == 0")
        for rec in records:
            assert rec not in sel


if __name__ == "__main__":
    __import__("standalone_test").main(globals())
