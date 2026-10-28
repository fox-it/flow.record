"""Declarative (subclass) syntax for defining records.

Besides the :class:`~flow.record.RecordDescriptor` API, records can also be
defined declaratively by subclassing :class:`RecordBase` and annotating fields,
like a ``dataclass`` or ``NamedTuple``. The metaclass builds the
:class:`~flow.record.RecordDescriptor` and folds the record behaviour into the
class, so instances are genuine ``Record`` objects while type checkers see a
typed constructor and attribute access (via :func:`typing.dataclass_transform`)::

    from datetime import datetime
    from typing import Annotated

    from flow.record.declarative import RecordBase, field


    class HttpRequest(RecordBase, name="http/request"):
        ts: datetime
        url: str  # native types map (e.g. str -> string)
        status: Annotated[int, "uint32"]  # or field(typename="uint32")
        remote: str


    record = HttpRequest(ts=datetime.now(), url="http://flow.record", status=200, remote="127.0.0.1")

Inheritance works as expected -- a subclass extends its parent's fields::

    class HttpResponse(HttpRequest, name="http/response"):
        body: bytes

Use ``field(init=False)`` for derived fields and populate them from ``InitVar``
inputs in a ``__post_init__`` hook::

    from dataclasses import InitVar


    class Host(RecordBase, name="example/host"):
        hostname: str = field(init=False)
        target: InitVar[object]

        def __post_init__(self, target: object) -> None:
            self.hostname = target.hostname

Note: field annotations are evaluated at runtime (via :func:`typing.get_type_hints`).
Projects using Ruff's ``flake8-type-checking`` (``TC``) rules should add
``RecordBase`` to the runtime-evaluated base classes once, so that imports used
only in field annotations are not moved into a ``TYPE_CHECKING`` block::

    [tool.ruff.lint.flake8-type-checking]
    runtime-evaluated-base-classes = ["flow.record.declarative.RecordBase"]
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, NamedTuple, get_args, get_origin, get_type_hints

from flow.record.base import (
    _FIELDTYPES_PREFIX,
    RECORD_VERSION,
    FieldType,
    Record,
    RecordDescriptor,
    RecordField,
    _default_is_trivial,
    _utcnow,
)
from flow.record.whitelist import WHITELIST

try:
    from typing import dataclass_transform  # novermin  # Python 3.11+
except ImportError:  # Python 3.10
    try:
        from typing_extensions import dataclass_transform
    except ImportError:
        # dataclass_transform is a typing-only marker with no runtime effect, so a
        # no-op keeps imports working without a typing_extensions runtime dependency.
        def dataclass_transform(**kwargs: Any) -> Callable[[Any], Any]:
            return lambda obj: obj


if TYPE_CHECKING:
    from collections.abc import Callable

PY_311_OR_HIGHER = sys.version_info >= (3, 11)

# Native Python type -> flow.record typename
# Use `field(typename=...)` or `Annotated[int, "..."]` for a precise type
_PY_TYPE_TO_TYPENAME: dict[type, str] = {
    str: "string",
    int: "varint",
    float: "float",
    bool: "boolean",
    bytes: "bytes",
    datetime: "datetime",
    Path: "path",
}

# Metadata key under which `field(typename=...)` stashes an explicit typename
_TYPENAME_KEY = "flow.record.typename"


def field(
    *,
    default: Any = dataclasses.MISSING,
    default_factory: Any = dataclasses.MISSING,
    init: bool = True,
    typename: str | None = None,
) -> Any:
    """Field specifier for declarative records, wrapping :func:`dataclasses.field`.

    Use in place of a bare annotation to set a ``default``/``default_factory``,
    mark a derived field with ``init=False``, or pin a ``typename``.
    """
    metadata = {_TYPENAME_KEY: typename} if typename is not None else {}
    kwargs: dict[str, Any] = {"init": init, "metadata": metadata}
    if default is not dataclasses.MISSING:
        kwargs["default"] = default
    if default_factory is not dataclasses.MISSING:
        kwargs["default_factory"] = default_factory
    return dataclasses.field(**kwargs)


def _resolve_typename(annotation: Any) -> str:
    """Map a resolved field annotation to a ``flow.record`` typename."""
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
    """Resolve a ``flow.record`` typename from a fieldtype class.

    Top-level types map directly (``uint32`` -> ``"uint32"``), namespaced types
    like :class:`~flow.record.fieldtypes.net.ipaddress` are matched against the
    whitelist by progressively shortening the module path, so classes that are
    re-exported one level up from where they are defined still resolve
    (``net.ip.ipaddress`` -> ``net.ipaddress``).
    """
    name = annotation.__name__
    module = annotation.__module__
    parts = module[len(_FIELDTYPES_PREFIX) + 1 :].split(".") if module.startswith(_FIELDTYPES_PREFIX + ".") else []

    # Try the most specific namespace first, then shorten towards the bare name
    for i in range(len(parts), -1, -1):
        namespace = ".".join(parts[:i])
        candidate = f"{namespace}.{name}" if namespace else name
        if candidate in WHITELIST:
            return candidate

    # Fall back to the bare class name, RecordDescriptor will validate the typename
    return name


def _is_classvar(hint: Any) -> bool:
    return hint is ClassVar or get_origin(hint) is ClassVar


def _is_initvar(hint: Any) -> bool:
    if isinstance(hint, str):
        text = hint.strip().removeprefix("dataclasses.")
        return text == "InitVar" or text.startswith("InitVar[")
    return hint is dataclasses.InitVar or type(hint) is dataclasses.InitVar


def _resolve_hints(cls: type) -> tuple[dict[str, Any], list[str]]:
    """Resolve merged field annotations, split into fields and init-only var names."""
    if PY_311_OR_HIGHER:
        fields: dict[str, Any] = {}
        initvars: list[str] = []

        for name, hint in get_type_hints(cls, include_extras=True).items():
            if _is_initvar(hint):
                initvars.append(name)
            else:
                fields[name] = hint

        return fields, initvars

    # Python 3.10 fallback: hide InitVar annotations from get_type_hints.
    initvars = []
    removed: list[tuple[dict[str, Any], str, Any]] = []
    for klass in reversed(cls.__mro__):
        if not (ann := klass.__dict__.get("__annotations__")):
            continue

        for name in list(ann):
            if _is_initvar(ann[name]):
                if name not in initvars:
                    initvars.append(name)

                removed.append((ann, name, ann[name]))
                del ann[name]

    try:
        hints = get_type_hints(cls, include_extras=True)
    finally:
        for ann, name, value in removed:
            ann[name] = value

    return hints, initvars


# Sentinel marking an init-only var that was not supplied to the constructor
_MISSING = object()


def _generate_init(
    init_field_names: list[str],
    derived_field_names: list[str],
    initvar_names: list[str],
    field_types: dict[str, Any],
    field_specs: dict[str, dataclasses.Field],
    has_post_init: bool,
) -> Callable[..., None]:
    """Build a specialised ``__init__`` for a declarative record class.

    The generated body is straight-line code with field defaults inlined.
    Assignments go through ``Record.__setattr__`` so values are still coerced to their fieldtypes.
    """
    if initvar_names and not has_post_init:
        raise TypeError(f"init-only vars {sorted(initvar_names)} require a __post_init__ hook")

    global_ns: dict[str, Any] = {
        "__utcnow": _utcnow,
        "__RECORD_VERSION": RECORD_VERSION,
        "__MISSING": _MISSING,
    }

    def default_expr(name: str) -> str | None:
        """Inline expression for a field's default, or ``None`` to use ``None``.

        An explicit ``field(default=...)``/``default_factory=...`` wins, otherwise
        the fieldtype's own default is used (``None`` for most types).
        """
        spec = field_specs.get(name)
        if spec is not None and spec.default is not dataclasses.MISSING:
            global_ns[gname := f"__default_{name}"] = spec.default
            return gname

        if spec is not None and spec.default_factory is not dataclasses.MISSING:
            global_ns[gname := f"__default_{name}"] = spec.default_factory
            return f"{gname}()"

        if _default_is_trivial(field_type := field_types[name]):
            return None

        global_ns[gname := f"__default_{name}"] = field_type.default
        return f"{gname}()"

    params = [f"{name}=None" for name in init_field_names]
    params += [f"{name}=__MISSING" for name in initvar_names]
    params += ["_source=None", "_classification=None", "_generated=None"]

    lines = [f"def __init__(__self, {', '.join(params)}):"]

    for name in init_field_names:
        if (expr := default_expr(name)) is None:
            lines.append(f"    __self.{name} = {name}")
        else:
            lines.append(f"    __self.{name} = {name} if {name} is not None else {expr}")

    for name in derived_field_names:
        expr = default_expr(name)
        lines.append(f"    __self.{name} = {expr or 'None'}")

    lines.append("    __self._source = _source")
    lines.append("    __self._classification = _classification")

    if initvar_names:
        lines.append("    __initvars = {}")
        for name in initvar_names:
            lines.append(f"    if {name} is not __MISSING:")
            lines.append(f"        __initvars[{name!r}] = {name}")
        lines.append("    __self.__post_init__(**__initvars)")
    elif has_post_init:
        lines.append("    __self.__post_init__()")

    lines.append("    __self._generated = _generated or __utcnow()")
    lines.append("    __self._version = __RECORD_VERSION")

    local_ns: dict[str, Any] = {}
    exec("\n".join(lines), global_ns, local_ns)
    return local_ns["__init__"]


@dataclass_transform(
    eq_default=True,
    kw_only_default=False,
    field_specifiers=(field, dataclasses.field, dataclasses.Field),
)
class _RecordMeta(type):
    """Metaclass that turns an annotated subclass into a record class."""

    if TYPE_CHECKING:
        __descriptor__: ClassVar[RecordDescriptor]

    def __new__(mcs, cls_name: str, bases: tuple[type, ...], namespace: dict[str, Any], **kwargs: Any):
        cls = super().__new__(mcs, cls_name, bases, namespace)

        # The base sentinel itself (no RecordBase ancestor): nothing to describe
        if not any(isinstance(b, _RecordMeta) for b in bases):
            return cls

        record_name = kwargs.get("name") or namespace.get("__record_name__", cls_name)

        hints, initvars = _resolve_hints(cls)

        field_tuples: list[tuple[str, str]] = []
        init_field_names: list[str] = []
        field_specs: dict[str, dataclasses.Field] = {}
        for fname, hint in hints.items():
            if fname.startswith("__") or _is_classvar(hint):
                continue

            spec = getattr(cls, fname, None)
            if is_field_spec := isinstance(spec, dataclasses.Field):
                field_specs[fname] = spec

            # Explicit `field(typename=...)` wins, else infer from the annotation
            typename = spec.metadata.get(_TYPENAME_KEY) if is_field_spec else None
            field_tuples.append((typename or _resolve_typename(hint), fname))

            # `field(init=False)` marks a derived field, not a constructor arg
            if not (is_field_spec and spec.init is False):
                init_field_names.append(fname)

        descriptor = RecordDescriptor(record_name, field_tuples)
        field_types: dict[str, Any] = {name: RecordField(name, typename).type for typename, name in field_tuples}
        for rname, rfield in RecordDescriptor.get_required_fields().items():
            field_types[rname] = rfield.type

        # Derived (`init=False`) fields are initialised from their default and
        # then populated by `__post_init__`. Keep them out of the constructor
        init_set = set(init_field_names)
        derived_field_names = [name for _, name in field_tuples if name not in init_set]
        # Resolve the `__post_init__` hook once so the generated `__init__`
        # doesn't probe for it on every construction
        has_post_init = callable(getattr(cls, "__post_init__", None))

        # `__slots__` is set as a plain attribute (the field-name list that
        # Record internals iterate), NOT a real slots declaration, so records
        # stay dict-based and multi-level inheritance is layout-conflict free
        record_cls: Any = cls
        record_cls._desc = descriptor
        record_cls._field_types = field_types
        record_cls.__slots__ = tuple(field_types.keys())
        record_cls.__descriptor__ = descriptor
        # Compile a constructor for this exact field set
        record_cls.__init__ = _generate_init(
            init_field_names, derived_field_names, initvars, field_types, field_specs, has_post_init
        )
        return cls

    def __init__(cls, cls_name: str, bases: tuple[type, ...], namespace: dict[str, Any], **kwargs: Any) -> None:
        # Swallow the `name=` (and any other) class keyword so `type.__init__` doesn't choke
        super().__init__(cls_name, bases, namespace)


class RecordBase(Record, metaclass=_RecordMeta):
    """Base class for declarative record definitions.

    Subclass and annotate fields. Set the record type name with ``name="cat/type"``
    (class keyword) or ``__record_name__``, defaulting to the class name.

    Declare init-only inputs with ``from dataclasses import InitVar`` and populate
    derived fields from them in ``__post_init__``.
    """

    if TYPE_CHECKING:
        __descriptor__: ClassVar[RecordDescriptor]


class FieldInfo(NamedTuple):
    """Type and optional docstring information for a declarative record field."""

    typename: str
    doc: str | None


def get_field_info(cls: type) -> dict[str, FieldInfo]:
    """Return a ``{field_name: FieldInfo}`` mapping for a record class.

    The ``typename`` always comes from the record descriptor. The ``doc`` is the
    PEP 224-style attribute docstring (a string literal directly following a field
    annotation), recovered from the class source. It is ``None`` when a field has
    no docstring or when the source cannot be read.
    """
    # Declarative records expose `__descriptor__`, classic record types expose `_desc`.
    descriptor: RecordDescriptor | None = getattr(cls, "__descriptor__", None) or getattr(cls, "_desc", None)
    if descriptor is None:
        raise TypeError(f"{cls!r} is not a record class")

    docstrings = _extract_field_docstrings(cls)
    return {name: FieldInfo(typename, docstrings.get(name)) for typename, name in descriptor.get_field_tuples()}


def _extract_field_docstrings(cls: type) -> dict[str, str]:
    """Best-effort attribute-docstring extraction across a record's MRO.

    Walks base-to-derived so more-derived docstrings win, and silently skips any
    class whose source is unavailable or cannot be parsed.
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

        # An attribute docstring is a bare string literal directly following the
        # field's annotation, so pair each node with the one after it
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
