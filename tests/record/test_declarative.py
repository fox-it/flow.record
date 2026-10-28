from __future__ import annotations

import inspect
import io
import re
from dataclasses import InitVar
from datetime import datetime, timezone
from typing import Annotated, Any

import pytest

from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.base import Record
from flow.record.declarative import FieldInfo, RecordBase, field, get_field_info
from flow.record.fieldtypes import net, string, uint32


def test_declarative_basic() -> None:
    class TestRecord(RecordBase, name="test/record"):
        url: str
        status: Annotated[int, "uint32"]

    r = TestRecord(url="http://flow.record", status=200)

    assert isinstance(r, Record)
    assert isinstance(r, TestRecord)
    assert r.url == "http://flow.record"
    assert r.status == 200

    # Values are coerced to their fieldtypes.
    assert isinstance(r.url, string)
    assert isinstance(r.status, uint32)


def test_declarative_name() -> None:
    class KwargName(RecordBase, name="test/kwarg"):
        a: int

    class AttrName(RecordBase):
        __record_name__ = "test/attr"
        a: int

    class DefaultName(RecordBase):
        a: int

    assert KwargName.__descriptor__.name == "test/kwarg"
    assert AttrName.__descriptor__.name == "test/attr"
    assert DefaultName.__descriptor__.name == "DefaultName"


def test_declarative_typenames() -> None:
    class TestRecord(RecordBase, name="test/types"):
        a: str
        b: int
        c: uint32
        d: Annotated[int, "uint16"]
        e: int = field(typename="uint32")

    assert TestRecord.__descriptor__.get_field_tuples() == (
        ("string", "a"),
        ("varint", "b"),
        ("uint32", "c"),
        ("uint16", "d"),
        ("uint32", "e"),
    )


def test_declarative_fieldtype_class_annotation() -> None:
    class TestRecord(RecordBase, name="test/fieldtype_class"):
        count: uint32  # top-level fieldtype class
        ip: net.ipaddress  # namespaced fieldtype class

    # Namespaced fieldtypes resolve to their whitelisted typename
    assert TestRecord.__descriptor__.get_field_tuples() == (
        ("uint32", "count"),
        ("net.ipaddress", "ip"),
    )

    r = TestRecord(count=5, ip="1.1.1.1")
    assert isinstance(r.count, uint32)
    assert isinstance(r.ip, net.ipaddress)
    assert str(r.ip) == "1.1.1.1"


def test_declarative_positional() -> None:
    class TestRecord(RecordBase, name="test/positional"):
        a: int
        b: str

    r = TestRecord(1, "two")
    assert r.a == 1
    assert r.b == "two"


def test_declarative_defaults() -> None:
    class TestRecord(RecordBase, name="test/default"):
        a: int = field(default=42)
        b: str = field(default_factory=lambda: "generated")

    # `field(default=...)`/`default_factory=...` are applied when no value is given.
    r = TestRecord()
    assert r.a == 42
    assert r.b == "generated"

    # Explicit values still win over the default.
    assert TestRecord(a=1).a == 1


def test_declarative_unexpected_keyword() -> None:
    class TestRecord(RecordBase, name="test/unexpected"):
        a: int

    with pytest.raises(TypeError):
        TestRecord(a=1, nope=2)


def test_declarative_inheritance() -> None:
    class Base(RecordBase, name="test/base"):
        a: int
        b: str

    class Child(Base, name="test/child"):
        c: int

    r = Child(a=1, b="two", c=3)

    assert isinstance(r, Base)
    assert isinstance(r, Child)
    # Fields are merged across the MRO, base fields first.
    assert Child.__descriptor__.get_field_tuples() == (
        ("varint", "a"),
        ("string", "b"),
        ("varint", "c"),
    )
    assert (r.a, r.b, r.c) == (1, "two", 3)


def test_declarative_post_init() -> None:
    class Target:
        hostname = "host01"
        domain = "example.com"

    class Base(RecordBase, name="test/target"):
        hostname: str = field(init=False)
        domain: str = field(init=False)
        _target: InitVar[Any]

        def __post_init__(self, _target: Any) -> None:
            self.hostname = _target.hostname
            self.domain = _target.domain

    class Child(Base, name="test/target_child"):
        a: int

    r = Child(a=1, _target=Target())

    assert r.hostname == "host01"
    assert r.domain == "example.com"
    assert r.a == 1
    # Init-only vars are not stored.
    assert "_target" not in r._asdict()


def test_declarative_init_false_excluded_from_constructor() -> None:
    class TestRecord(RecordBase, name="test/init_false"):
        a: int
        b: str = field(init=False)

    # `a` is a constructor argument; `b` (init=False) is not part of the signature
    # and is initialised to its default instead.
    r = TestRecord(a=1)
    assert r.a == 1
    assert r.b is None

    # Only init fields count towards positional binding.
    assert TestRecord(2).a == 2

    # The derived field is rejected as a constructor argument.
    with pytest.raises(TypeError):
        TestRecord(a=1, b="nope")


def test_declarative_initvar_without_post_init() -> None:
    # An init-only var with no __post_init__ to consume it is a definition error.
    with pytest.raises(TypeError, match=re.escape("init-only vars ['_target'] require a __post_init__ hook")):

        class TestRecord(RecordBase, name="test/no_post_init"):
            _target: InitVar[Any]


def test_declarative_roundtrip() -> None:
    class TestRecord(RecordBase, name="test/roundtrip"):
        ts: datetime
        url: str
        status: int = field(typename="uint32")

    r = TestRecord(ts=datetime.now(timezone.utc), url="http://flow.record", status=200)

    buf = io.BytesIO()
    writer = RecordWriter(fileobj=buf)
    writer.write(r)
    writer.flush()
    buf.seek(0)

    [read] = list(RecordReader(fileobj=buf))
    assert read.ts == r.ts
    assert read.url == r.url
    assert read.status == r.status
    assert read._desc.name == "test/roundtrip"


def test_declarative_field_docstring() -> None:
    class TestRecord(RecordBase, name="test/doc"):
        url: str
        """The requested URL."""
        status: int

    # An inline field docstring must not interfere with the record definition.
    r = TestRecord(url="http://flow.record", status=200)
    assert r.url == "http://flow.record"

    assert get_field_info(TestRecord) == {
        "url": FieldInfo("string", "The requested URL."),
        "status": FieldInfo("varint", None),
    }


def test_declarative_field_docstring_inherited() -> None:
    class Base(RecordBase, name="test/doc_base"):
        a: int
        """Field a."""

    class Child(Base, name="test/doc_child"):
        b: str
        """Field b."""

    docs = get_field_info(Child)
    # Docstrings are gathered across the whole MRO.
    assert docs["a"] == FieldInfo("varint", "Field a.")
    assert docs["b"] == FieldInfo("string", "Field b.")


def test_declarative_field_docstring_source_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    class TestRecord(RecordBase, name="test/doc_nosrc"):
        url: str
        """The requested URL."""

    def _raise(_: object) -> str:
        raise OSError("source not available")

    monkeypatch.setattr(inspect, "getsource", _raise)

    # Typenames still resolve; docstrings degrade to None instead of raising.
    assert get_field_info(TestRecord) == {"url": FieldInfo("string", None)}


def test_declarative_field_info_classic_record() -> None:
    # A classically generated record type has no retrievable source (it is exec'd)
    # and no attribute docstrings; get_field_info must still resolve typenames and
    # degrade docstrings to None without blowing up.
    classic = RecordDescriptor("test/classic", [("string", "url"), ("uint32", "status")]).recordType

    assert get_field_info(classic) == {
        "url": FieldInfo("string", None),
        "status": FieldInfo("uint32", None),
    }


def test_declarative_field_docs_not_a_record() -> None:
    with pytest.raises(TypeError):
        get_field_info(int)
