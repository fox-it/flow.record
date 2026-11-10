from __future__ import annotations

import inspect
import io
import re
from dataclasses import InitVar
from datetime import datetime, timezone
from textwrap import dedent
from typing import Annotated, Any, Optional

import pytest

from flow.record import RecordDescriptor, RecordReader, RecordWriter
from flow.record.base import Record
from flow.record.declarative import FieldInfo, RecordBase, field, get_field_info
from flow.record.fieldtypes import net, string, uint32, varint


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
        f: str | None
        g: Optional[int]  # noqa: UP045
        h: uint32 | None
        i: Annotated[int, "uint16"] | None
        j: None | datetime = None

    assert TestRecord.__descriptor__.get_field_tuples() == (
        ("string", "a"),
        ("varint", "b"),
        ("uint32", "c"),
        ("uint16", "d"),
        ("uint32", "e"),
        ("string", "f"),
        ("varint", "g"),
        ("uint32", "h"),
        ("uint16", "i"),
        ("datetime", "j"),
    )


@pytest.mark.parametrize("annotation", [object, int | str, int | str | None])
def test_declarative_unmapped_annotation(annotation: Any) -> None:
    """Test that an annotation without a flow.record fieldtype, such as a union of two types, raises an error."""
    with pytest.raises(TypeError) as exc:

        class TestRecord(RecordBase, name="test/unmapped"):
            a: annotation

    assert str(exc.value) == f"Failed to map annotation {annotation!r} to a flow.record fieldtype"


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
        c: int = 7

    # `field(default=...)`/`default_factory=...` are applied when no value is given.
    r = TestRecord()
    assert r.a == 42
    assert r.b == "generated"
    assert r.c == 7

    # Explicit values still win over the default.
    assert TestRecord(a=1).a == 1
    assert TestRecord(c=1).c == 1


def test_declarative_unexpected_keyword() -> None:
    class TestRecord(RecordBase, name="test/unexpected"):
        a: int

    with pytest.raises(TypeError, match=r"^__init__\(\) got an unexpected keyword argument 'nope'$"):
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


def test_declarative_local_names() -> None:
    """Test that annotations can refer to names in the scope of the class statement, also in a subclass elsewhere."""

    def define() -> tuple[type[RecordBase], type]:
        class Target:
            hostname = "host01"

        Port = Annotated[int, "uint16"]

        class Base(RecordBase, name="test/local_base"):
            port: Port
            hostname: str = field(init=False)
            target: InitVar[Target]

            def __post_init__(self, target: Target) -> None:
                self.hostname = target.hostname

        return Base, Target

    Base, Target = define()

    class Child(Base, name="test/local_child"):
        a: int

    assert Child.__descriptor__.get_field_tuples() == (
        ("uint16", "port"),
        ("string", "hostname"),
        ("varint", "a"),
    )
    r = Child(port=80, target=Target(), a=1)
    assert (r.port, r.hostname, r.a) == (80, "host01", 1)


@pytest.mark.parametrize("future", ["from __future__ import annotations", ""], ids=["future", "no-future"])
def test_declarative_annotations_evaluation(future: str) -> None:
    """Test annotations that are strings, evaluated by Python itself, or (since Python 3.14) evaluated lazily."""
    source = f"""
    {future}
    from typing import Annotated

    from flow.record.declarative import RecordBase

    Status = Annotated[int, "uint32"]

    class TestRecord(RecordBase, name="test/evaluation"):
        Port = Annotated[int, "uint16"]

        status: Status
        port: Port
        url: "str"
    """
    namespace = {}
    exec(compile(dedent(source), "<test>", "exec", dont_inherit=True), namespace)

    assert namespace["TestRecord"].__descriptor__.get_field_tuples() == (
        ("uint32", "status"),
        ("uint16", "port"),
        ("string", "url"),
    )


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
    with pytest.raises(TypeError, match=r"^__init__\(\) got an unexpected keyword argument 'b'$"):
        TestRecord(a=1, b="nope")


def test_declarative_post_init_after_fields() -> None:
    """Test that ``__post_init__`` runs after all fields are set, including the reserved fields."""
    asdicts = []

    class TestRecord(RecordBase, name="test/post_init_after_fields"):
        a: int

        def __post_init__(self) -> None:
            asdicts.append(self._asdict())

    r = TestRecord(a=1)
    assert asdicts == [r._asdict()]


def test_declarative_initvar_without_post_init() -> None:
    # An init-only var with no __post_init__ to consume it is a definition error.
    with pytest.raises(TypeError, match=re.escape("init-only vars ['_target'] require a __post_init__ hook")):

        class TestRecord(RecordBase, name="test/no_post_init"):
            _target: InitVar[Any]


def test_declarative_replace() -> None:
    """Test that ``_replace`` copies a record with new values, keeping the fields set in ``__post_init__``."""

    class TestRecord(RecordBase, name="test/replace"):
        a: int
        b: str = field(init=False)
        _value: InitVar[str]

        def __post_init__(self, _value: str) -> None:
            self.b = _value

    r = TestRecord(a=1, _value="two")
    replaced = r._replace(a=3)

    assert isinstance(replaced, TestRecord)
    assert replaced._asdict() == {**r._asdict(), "a": 3}
    assert isinstance(replaced.a, varint)
    assert r.a == 1

    with pytest.raises(ValueError, match=r"^Got unexpected field names: \['nope'\]$"):
        r._replace(nope=1)


def test_declarative_from_asdict() -> None:
    """Test that a record can be created from the fields of another one, including the reserved fields."""

    class TestRecord(RecordBase, name="test/from_asdict"):
        a: int

    r = TestRecord(a=1, _source="source")
    assert TestRecord(**r._asdict())._asdict() == r._asdict()


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


def test_declarative_matches_classic() -> None:
    """Test that a declarative record class is shaped like the record class of its descriptor."""

    class TestRecord(RecordBase, name="test/matches_classic"):
        ts: datetime
        url: str
        status: int = field(typename="uint32")

    classic = TestRecord.__descriptor__.recordType
    assert TestRecord._field_types == classic._field_types
    assert TestRecord.__slots__ == classic.__slots__
    # The first parameter is self, which has a different name
    assert (
        list(inspect.signature(TestRecord.__init__).parameters.values())[1:]
        == list(inspect.signature(classic.__init__).parameters.values())[1:]
    )

    ts = datetime.now(timezone.utc)
    record = TestRecord(ts, "http://flow.record", 200, _generated=ts)
    classic_record = classic(ts, "http://flow.record", 200, _generated=ts)
    assert record._pack() == classic_record._pack()
    assert record == classic_record
    assert hash(record) == hash(classic_record)


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
    with pytest.raises(TypeError, match=r"^<class 'int'> is not a record class$"):
        get_field_info(int)
