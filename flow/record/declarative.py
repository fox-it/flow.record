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

Every field can be ``None``, so ``X | None`` is technically the more correct type hint.
A field annotated with ``X | None`` has the same field type as ``X``.

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
import functools
import inspect
import itertools
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from types import NoneType, UnionType
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, NamedTuple, Union, get_args, get_origin

from flow.record.base import (
    _FIELDTYPES_PREFIX,
    RECORD_VERSION,
    RESERVED_FIELDS,
    FieldType,
    Record,
    RecordDescriptor,
    _default_is_trivial,
    _replace_names,
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
    from types import CodeType, FunctionType

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


# The field of an annotation without a value, which is shared because fields are not changed
_NO_DEFAULT = field()


def _resolve_typename(annotation: Any) -> str:
    """Return the flow.record typename of a field annotation."""
    # Most annotations are a class, so check that first
    if isinstance(annotation, type):
        if issubclass(annotation, FieldType):
            return _fieldtype_typename(annotation)

        if annotation in _PY_TYPE_TO_TYPENAME:
            return _PY_TYPE_TO_TYPENAME[annotation]

    elif get_origin(annotation) is Annotated:
        base, *metadata = get_args(annotation)
        for meta in metadata:
            if isinstance(meta, str):
                return meta
        return _resolve_typename(base)

    # Every field can be None, so `X | None` and `Optional[X]` have the typename of X
    elif get_origin(annotation) in (Union, UnionType):
        args = [arg for arg in get_args(annotation) if arg is not NoneType]
        if len(args) == 1:
            return _resolve_typename(args[0])

    raise TypeError(f"Failed to map annotation {annotation!r} to a flow.record fieldtype")


@functools.lru_cache(maxsize=256)
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


@functools.lru_cache(maxsize=4096)
def _compile_annotation(source: str) -> CodeType:
    """Compile an annotation string once, as most annotations are the same few strings."""
    return compile(source, "<string>", "eval")


# Marks an init-only variable that was not given to the constructor
_MISSING = object()

DECLARATIVE_INIT_TEMPLATE = """
def __init__(__self, {args}):
{set_fields}
    _setattr(__self, "_version", _version_value)
{post_init}
"""

# How __init__() sets a field: to the value, or to the default of the field. Like Record.__setattr__(), it converts
# the value to the field type, and then stores it with object.__setattr__(), which skips the Python code of
# Record.__setattr__(). Storing it in __dict__ directly is faster, but makes reading the attributes slower.
DECLARATIVE_SET_FIELD_TEMPLATE = """\
    if {name} is None and _default_{name} is not None:
        {name} = _default_{name}()
    if {name} is not None and not isinstance({name}, _type_{name}):
        {name} = _type_{name}({name})
    _setattr(__self, "{name}", {name})
"""

# How __init__() passes an init-only var to __post_init__(), if it was given
DECLARATIVE_SET_INITVAR_TEMPLATE = """\
    if {name} is not _MISSING:
        __initvars["{name}"] = {name}
"""


# The globals of the reserved fields in the compiled __init__, which are the same for every declarative record class.
# Like in a classic record, _generated is the current time if it's not given.
_RESERVED_GLOBALS = {
    "_version_value": RecordDescriptor.get_required_fields()["_version"].type(RECORD_VERSION),
    **{f"_type_{name}": field.type for name, field in RecordDescriptor.get_required_fields().items()},
    **{f"_default_{name}": None for name in RESERVED_FIELDS},
    "_default__generated": _utcnow,
}


@functools.lru_cache(maxsize=256)
def _compile_init(init: tuple[bool, ...], initvar_count: int, has_post_init: bool) -> FunctionType:
    """Compile the ``__init__`` of declarative record classes with the same shape.

    Compiling takes most of the time of creating a declarative record class, so it's done once for every shape. The
    fields and init-only vars are named ``_0``, ``_1``, etc. in the compiled ``__init__``, which ``_generate_init()``
    replaces with their names. It looks up everything that depends on the field types in its globals.

    Args:
        init: For every field, whether it is an argument.
        initvar_count: The number of init-only vars, which are the arguments after the fields.
        has_post_init: Whether to call ``__post_init__``.
    """
    names = [f"_{i}" for i in range(len(init) + initvar_count)]
    fields, initvars = names[: len(init)], names[len(init) :]
    args = [f"{name}=None" for name, is_arg in zip(fields, init, strict=True) if is_arg]
    args += [f"{name}=_MISSING" for name in initvars]
    args += [f"{name}=None" for name in RESERVED_FIELDS]

    # A field that is not an argument (init=False) starts without a value, so it's set to its default
    set_fields = "".join(
        ("" if is_arg else f"    {name} = None\n") + DECLARATIVE_SET_FIELD_TEMPLATE.format(name=name)
        for name, is_arg in zip(fields, init, strict=True)
    )
    set_fields += "".join(DECLARATIVE_SET_FIELD_TEMPLATE.format(name=name) for name in RESERVED_FIELDS)

    post_init = ""
    if has_post_init:
        post_init = "    __initvars = {}\n"
        post_init += "".join(DECLARATIVE_SET_INITVAR_TEMPLATE.format(name=name) for name in initvars)
        post_init += "    __self.__post_init__(**__initvars)\n"

    source = DECLARATIVE_INIT_TEMPLATE.format(args=", ".join(args), set_fields=set_fields, post_init=post_init)
    exec(source, namespace := {"_MISSING": _MISSING})
    return namespace["__init__"]


def _generate_init(
    cls: type[RecordBase],
    specs: dict[str, dataclasses.Field],
    initvar_names: list[str],
    has_post_init: bool,
) -> Callable[..., None]:
    """Generate the ``__init__`` of a declarative record class.

    Like in a classic record class, the defaults are the defaults of the field types, unless the field has its own
    default, and ``_generated`` defaults to the current time.
    """
    # Maps the names in the compiled __init__ to the names of the fields and init-only vars
    names = {f"_{i}": name for i, name in enumerate([*specs, *initvar_names])}

    _globals = {**_RESERVED_GLOBALS, "_MISSING": _MISSING, "_setattr": object.__setattr__}
    for template_name, (name, spec) in zip(names, specs.items(), strict=False):
        field_type = cls._field_types[name]
        _globals[f"_type_{template_name}"] = field_type
        if spec.default is not dataclasses.MISSING:
            # A function that returns the same value every time
            _globals[f"_default_{template_name}"] = itertools.repeat(spec.default).__next__
        elif spec.default_factory is not dataclasses.MISSING:
            _globals[f"_default_{template_name}"] = spec.default_factory
        else:
            _globals[f"_default_{template_name}"] = None if _default_is_trivial(field_type) else field_type.default

    template = _compile_init(tuple(spec.init for spec in specs.values()), len(initvar_names), has_post_init)
    function = _replace_names(template, names, _globals)
    function.__qualname__ = f"{cls.__name__}.__init__"
    return function


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
        # defined in a function. In a module, its locals are its globals, which don't need to be copied.
        frame = sys._getframe(1)
        localns = vars(cls) if frame.f_locals is frame.f_globals else {**frame.f_locals, **vars(cls)}
        cls.__record_annotations__ = {}
        for fname, annotation in inspect.get_annotations(cls).items():
            # With `from __future__ import annotations`, a quoted annotation is a string in a string
            while isinstance(annotation, str):
                annotation = eval(_compile_annotation(annotation), frame.f_globals, localns)
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
                # An init-only var is an argument of __init__ next to the reserved fields
                if fname in RESERVED_FIELDS:
                    raise TypeError(f"init-only var {fname!r} has the name of a reserved field")
                initvar_names.append(fname)
                continue

            # Like in a dataclass, `a: int = 1` is the same as `a: int = field(default=1)`
            spec = getattr(cls, fname, _NO_DEFAULT)
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
        cls._field_types = descriptor.recordType._field_types
        cls.__slots__ = descriptor.recordType.__slots__
        if "__init__" in vars(cls):
            raise TypeError(f"{cls.__name__} defines __init__, which declarative records generate, use __post_init__")
        cls.__init__ = _generate_init(cls, specs, initvar_names, has_post_init)

    def _replace(self, **kwds) -> Record:
        # Copy instead of calling the constructor, which doesn't accept `init=False` fields and needs the `InitVar`
        # arguments of `__post_init__`
        if unknown := [k for k in kwds if k not in self.__slots__]:
            raise ValueError(f"Got unexpected field names: {unknown!r}")

        result = copy.copy(self)
        for k, v in kwds.items():
            setattr(result, k, v)
        return result

    # The record class of the descriptor has faster versions of these methods, which only read the fields by name, so
    # they also work on declarative records
    def _pack(self, unversioned: bool = False, excluded_fields: list | None = None) -> tuple[tuple[str, int], tuple]:
        return self._desc.recordType._pack(self, unversioned, excluded_fields)

    def _asdict(self, fields: list[str] | None = None, exclude: list[str] | None = None) -> dict[str, Any]:
        return self._desc.recordType._asdict(self, fields, exclude)

    def __repr__(self) -> str:
        return self._desc.recordType.__repr__(self)


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
