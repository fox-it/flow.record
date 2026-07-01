"""Declarative syntax for defining records.

Instead of with a :class:`~flow.record.RecordDescriptor`, records can be defined by subclassing :class:`RecordBase`
and annotating the fields, like a ``dataclass``::

    from datetime import datetime
    from typing import Annotated

    from flow.record.declarative import RecordBase, field


    class HttpRequest(RecordBase, name="http/request"):
        ts: datetime
        url: str  # Python types map to a field type, e.g. str to string
        status: Annotated[int, "uint32"]  # or field(typename="uint32")
        remote: str


    record = HttpRequest(ts=datetime.now(), url="http://flow.record", status=200, remote="127.0.0.1")

The instances are regular records. A subclass starts with the fields of its parent::

    class HttpResponse(HttpRequest, name="http/response"):
        body: bytes

A field can have a default (``status: int = 200``), or be set in a ``__post_init__`` method with ``field(init=False)``.
The ``__post_init__`` method receives the ``InitVar`` arguments of the constructor::

    from dataclasses import InitVar


    class Host(RecordBase, name="example/host"):
        hostname: str = field(init=False)
        target: InitVar[object]

        def __post_init__(self, target: object) -> None:
            self.hostname = target.hostname

The declarative class is currently mostly a nicety for type checking. Internally, it defines a regular
:class:`~flow.record.RecordDescriptor`, and packing a record only stores that descriptor and the field values. So
declarative records don't round-trip: unpacking one returns a record of the record class of the descriptor, not an
instance of the declarative class.

Field annotations are evaluated when the class is created. Projects using Ruff's ``flake8-type-checking`` (``TC``)
rules should add :class:`RecordBase` to the runtime-evaluated base classes, so that imports only used in field
annotations are not moved into a ``TYPE_CHECKING`` block::

    [tool.ruff.lint.flake8-type-checking]
    runtime-evaluated-base-classes = ["flow.record.declarative.RecordBase"]
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import inspect
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, NamedTuple, get_args, get_origin

from flow.record.base import (
    _FIELDTYPES_PREFIX,
    RECORD_VERSION,
    FieldType,
    Record,
    RecordDescriptor,
    _default_is_trivial,
    _utcnow,
)
from flow.record.whitelist import WHITELIST

if sys.version_info >= (3, 11):
    from typing import dataclass_transform  # novermin
elif TYPE_CHECKING:
    from typing_extensions import dataclass_transform
else:
    # Only type checkers use dataclass_transform, so typing_extensions is not a runtime dependency.
    def dataclass_transform(**kwargs: Any) -> Callable[[Any], Any]:
        return lambda obj: obj


if TYPE_CHECKING:
    from collections.abc import Callable

# Python type -> flow.record typename
# Use `field(typename=...)` or `Annotated[int, "..."]` for a more specific type
_PY_TYPE_TO_TYPENAME: dict[type, str] = {
    str: "string",
    int: "varint",
    float: "float",
    bool: "boolean",
    bytes: "bytes",
    datetime: "datetime",
    Path: "path",
}

# Metadata key for the typename of `field(typename=...)`
_TYPENAME_KEY = "flow.record.typename"


def field(
    *,
    default: Any = dataclasses.MISSING,
    default_factory: Any = dataclasses.MISSING,
    init: bool = True,
    typename: str | None = None,
) -> Any:
    """Describe a field of a declarative record, like :func:`dataclasses.field`.

    Args:
        default: The value of the field if it is not given.
        default_factory: A function without arguments that returns the value of the field if it is not given.
        init: Whether the field is an argument of the constructor. If not, it can be set in ``__post_init__``.
        typename: The flow.record typename of the field, instead of the one of the annotation.
    """
    metadata = {_TYPENAME_KEY: typename} if typename is not None else {}
    return dataclasses.field(default=default, default_factory=default_factory, init=init, metadata=metadata)


def _resolve_typename(annotation: Any) -> str:
    """Return the flow.record typename of a field annotation."""
    if get_origin(annotation) is Annotated:
        base, *metadata = get_args(annotation)
        for meta in metadata:
            if isinstance(meta, str):
                return meta
        annotation = base

    if isinstance(annotation, type) and issubclass(annotation, FieldType):
        return _fieldtype_typename(annotation)

    if isinstance(annotation, type) and annotation in _PY_TYPE_TO_TYPENAME:
        return _PY_TYPE_TO_TYPENAME[annotation]

    raise TypeError(f"Failed to map annotation {annotation!r} to a flow.record fieldtype")


def _fieldtype_typename(annotation: type[FieldType]) -> str:
    """Return the flow.record typename of a field type class.

    Field types in a namespace are looked up in the whitelist, starting with the module that defines them and
    then each parent package. So ``flow.record.fieldtypes.net.ip.ipaddress`` is ``net.ipaddress``, because the
    ``net`` package exports it.
    """
    name = annotation.__name__
    module = annotation.__module__
    parts = module[len(_FIELDTYPES_PREFIX) + 1 :].split(".") if module.startswith(_FIELDTYPES_PREFIX + ".") else []

    for i in range(len(parts), -1, -1):
        namespace = ".".join(parts[:i])
        candidate = f"{namespace}.{name}" if namespace else name
        if candidate in WHITELIST:
            return candidate

    # RecordDescriptor validates the typename
    return name


# Marks an init-only variable that was not given to the constructor
_MISSING = object()


def _generate_init(
    specs: dict[str, dataclasses.Field],
    field_types: dict[str, type[FieldType]],
    initvar_names: list[str],
    has_post_init: bool,
) -> Callable[..., None]:
    """Generate the ``__init__`` of a declarative record class.

    Like in a classic record class, the values are assigned with ``Record.__setattr__``, which converts them to their
    field type.
    """
    global_ns: dict[str, Any] = {
        "__utcnow": _utcnow,
        "__RECORD_VERSION": RECORD_VERSION,
        "__MISSING": _MISSING,
    }

    params = []
    lines = []
    for name, spec in specs.items():
        if spec.default is not dataclasses.MISSING:
            global_ns[f"__default_{name}"] = spec.default
            default = f"__default_{name}"
        elif spec.default_factory is not dataclasses.MISSING:
            global_ns[f"__default_{name}"] = spec.default_factory
            default = f"__default_{name}()"
        elif not _default_is_trivial(field_types[name]):
            global_ns[f"__default_{name}"] = field_types[name].default
            default = f"__default_{name}()"
        else:
            default = None

        if not spec.init:
            lines.append(f"    __self.{name} = {default}")
            continue

        params.append(f"{name}=None")
        if default is None:
            lines.append(f"    __self.{name} = {name}")
        else:
            lines.append(f"    __self.{name} = {name} if {name} is not None else {default}")

    params += [f"{name}=__MISSING" for name in initvar_names]
    params += ["_source=None", "_classification=None", "_generated=None", "_version=None"]

    lines.append("    __self._source = _source")
    lines.append("    __self._classification = _classification")
    lines.append("    __self._generated = _generated or __utcnow()")
    lines.append("    __self._version = __RECORD_VERSION")

    if initvar_names:
        lines.append("    __initvars = {}")
        for name in initvar_names:
            lines.append(f"    if {name} is not __MISSING:")
            lines.append(f"        __initvars[{name!r}] = {name}")
        lines.append("    __self.__post_init__(**__initvars)")
    elif has_post_init:
        lines.append("    __self.__post_init__()")

    local_ns: dict[str, Any] = {}
    exec("\n".join([f"def __init__(__self, {', '.join(params)}):", *lines]), global_ns, local_ns)
    return local_ns["__init__"]


@dataclass_transform(
    eq_default=True,
    kw_only_default=False,
    field_specifiers=(field, dataclasses.field, dataclasses.Field),
)
class RecordBase(Record):
    """Base class for declarative records.

    For example::

        class HttpRequest(RecordBase, name="http/request"):
            url: str
            status: Annotated[int, "uint32"]

    The record name is the ``name`` class keyword argument, the ``__record_name__`` class attribute or the class name.
    See :mod:`flow.record.declarative`.
    """

    if TYPE_CHECKING:
        __descriptor__: ClassVar[RecordDescriptor]
        # The evaluated annotations of the class itself, which its subclasses inherit
        __record_annotations__: ClassVar[dict[str, Any]]

    def __init_subclass__(cls, *, name: str | None = None, **kwargs):
        super().__init_subclass__(**kwargs)

        # The scope of the class statement. Its locals are needed to evaluate annotations that refer to names
        # defined in a function.
        frame = sys._getframe(1)
        localns = {**frame.f_locals, **vars(cls)}
        cls.__record_annotations__ = {}
        for fname, annotation in inspect.get_annotations(cls).items():
            # With `from __future__ import annotations`, a quoted annotation is a string in a string
            while isinstance(annotation, str):
                annotation = eval(annotation, frame.f_globals, localns)
            cls.__record_annotations__[fname] = annotation

        annotations = {}
        for klass in reversed(cls.__mro__):
            annotations.update(vars(klass).get("__record_annotations__", {}))

        field_tuples: list[tuple[str, str]] = []
        specs: dict[str, dataclasses.Field] = {}
        initvar_names: list[str] = []
        for fname, annotation in annotations.items():
            if fname.startswith("__") or annotation is ClassVar or get_origin(annotation) is ClassVar:
                continue

            if annotation is dataclasses.InitVar or isinstance(annotation, dataclasses.InitVar):
                initvar_names.append(fname)
                continue

            # Like in a dataclass, `a: int = 1` is the same as `a: int = field(default=1)`
            spec = getattr(cls, fname, dataclasses.MISSING)
            if not isinstance(spec, dataclasses.Field):
                spec = field(default=spec)
            specs[fname] = spec

            field_tuples.append((spec.metadata.get(_TYPENAME_KEY) or _resolve_typename(annotation), fname))

        has_post_init = callable(getattr(cls, "__post_init__", None))
        if initvar_names and not has_post_init:
            raise TypeError(f"init-only vars {sorted(initvar_names)} require a __post_init__ hook")

        descriptor = RecordDescriptor(name or vars(cls).get("__record_name__", cls.__name__), field_tuples)
        cls._desc = cls.__descriptor__ = descriptor
        # `__slots__` is only the list of field names that Record uses, so instances still have a `__dict__` and
        # multiple inheritance doesn't run into layout conflicts.
        cls._field_types = {name: f.type for name, f in descriptor.get_all_fields().items()}
        cls.__slots__ = tuple(cls._field_types)
        cls.__init__ = _generate_init(specs, cls._field_types, initvar_names, has_post_init)

    def _replace(self, **kwds) -> Record:
        # Copy instead of calling the constructor, which doesn't accept `init=False` fields and needs the `InitVar`
        # arguments of `__post_init__`
        if unknown := [k for k in kwds if k not in self.__slots__]:
            raise ValueError(f"Got unexpected field names: {unknown!r}")

        result = copy.copy(self)
        for k, v in kwds.items():
            setattr(result, k, v)
        return result


class FieldInfo(NamedTuple):
    """The typename and docstring of a field of a record class."""

    typename: str
    doc: str | None


def get_field_info(cls: type) -> dict[str, FieldInfo]:
    """Return the typename and docstring of each field of a record class.

    The docstring of a field is a string literal directly after its annotation, as used by Sphinx. It is ``None`` if
    the field has no docstring or the source of the class is not available.
    """
    descriptor: RecordDescriptor | None = getattr(cls, "_desc", None)
    if descriptor is None:
        raise TypeError(f"{cls!r} is not a record class")

    docstrings = _extract_field_docstrings(cls)
    return {name: FieldInfo(typename, docstrings.get(name)) for typename, name in descriptor.get_field_tuples()}


def _extract_field_docstrings(cls: type) -> dict[str, str]:
    """Return the field docstrings of a declarative record class and its parents.

    A docstring in a subclass replaces the one of its parent. Classes without available source are skipped.
    """
    docstrings: dict[str, str] = {}

    for klass in reversed(cls.__mro__):
        if "__descriptor__" not in vars(klass):
            continue

        try:
            (class_def,) = ast.parse(textwrap.dedent(inspect.getsource(klass))).body
        except (OSError, TypeError, SyntaxError, ValueError):
            continue

        if not isinstance(class_def, ast.ClassDef):
            continue

        # Pair each statement with the one after it, to find a string literal after an annotation
        for annotation, following in zip(class_def.body, class_def.body[1:], strict=False):
            if (
                isinstance(annotation, ast.AnnAssign)
                and isinstance(annotation.target, ast.Name)
                and isinstance(following, ast.Expr)
                and isinstance(following.value, ast.Constant)
                and isinstance(following.value.value, str)
            ):
                docstrings[annotation.target.id] = following.value.value

    return docstrings
