from flow.record import RecordDescriptor
from flow.record.selector import CompiledSelector as Selector


def test_selector_func_name():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )
    assert TestRecord(None, None) not in Selector("name(r) == 'foo/bar'")
    assert TestRecord(None, None) in Selector("name(r) == 'test/record'")


def test_selector():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )

    assert TestRecord("foo", "bar") in Selector("r.query == 'foo'")
    assert TestRecord(None, None) not in Selector("r.query == 'foo'")
    assert TestRecord(None, None) not in Selector("name(r.query) == 'XX'")


def test_non_existing_field():
    TestRecord = RecordDescriptor(
        "test/record",
        [
            ("string", "query"),
            ("string", "url"),
        ],
    )

    assert TestRecord("foo", "bar") not in Selector("r.query and r.non_existing_field")
    assert TestRecord("foo", "bar") in Selector("not r.non_existing_field")
    assert TestRecord("foo", "bar") in Selector("r.query and r.url and not r.non_existing_field")


if __name__ == "__main__":
    __import__("standalone_test").main(globals())
