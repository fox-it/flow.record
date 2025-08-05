from __future__ import annotations
import __future__

import ast
import operator
import re
from typing import TYPE_CHECKING, Any, Callable

from flow.record.base import GroupedRecord, Record, dynamic_fieldtype
from flow.record.fieldtypes import net
from flow.record.whitelist import WHITELIST, WHITELIST_TREE

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    import astor

    HAVE_ASTOR = True
except ImportError:
    HAVE_ASTOR = False


AST_OPERATORS = {
    ast.Add: operator.add,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.And: operator.and_,
    ast.Or: operator.or_,
    ast.Not: operator.not_,
    ast.Mod: operator.mod,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
}

AST_COMPARATORS = {
    ast.Eq: operator.eq,
    ast.In: lambda left, right: (
        False if (isinstance(left, NoneObject) or isinstance(right, NoneObject)) else operator.contains(right, left)
    ),
    ast.NotIn: lambda left, right: (
        False
        if (isinstance(left, NoneObject) or isinstance(right, NoneObject))
        else operator.contains(right, left) is False
    ),
    ast.NotEq: operator.ne,
    ast.Gt: operator.gt,
    ast.Lt: operator.lt,
    ast.GtE: operator.ge,
    ast.LtE: operator.le,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}


class NoneObject:
    """Returned in the Selector matching if a field does not exist on the Record.

    NoneObject is used to override some comparators like __contains__.
    """

    def __eq__(a, b: object) -> bool:
        return False

    def __ne__(a, b: object) -> bool:
        return False

    def __lt__(a, b: object) -> bool:
        return False

    def __gt__(a, b: object) -> bool:
        return False

    def __lte__(a, b: object) -> bool:
        return False

    def __gte__(a, b: object) -> bool:
        return False

    def __noteq__(a, b: object) -> bool:
        return False

    def __contains__(a, b: object) -> bool:
        return False

    def __len__(self) -> int:
        return 0


NONE_OBJECT = NoneObject()


class InvalidSelectorError(Exception):
    pass


class InvalidOperation(Exception):
    pass


def lower(s: str | Any) -> str:
    """Return lowercased string, otherwise `s` if not string type."""
    if isinstance(s, str):
        return s.lower()
    return s


def upper(s: str | Any) -> str | Any:
    """Return uppercased string, otherwise `s` if not string type."""
    if isinstance(s, str):
        return s.upper()
    return s


def names(r: Record | WrappedRecord | GroupedRecord) -> set[str]:
    """Return the available names as a set in the Record otherwise ['UnknownRecord']."""
    if isinstance(r, GroupedRecord):
        return {sub_record._desc.name for sub_record in r.records}
    if isinstance(r, (Record, WrappedRecord)):
        return {r._desc.name}
    return ["UnknownRecord"]


def name(r: Record | WrappedRecord) -> str:
    """Return the name of the Record otherwise 'UnknownRecord'."""
    if isinstance(r, (Record, WrappedRecord)):
        return r._desc.name
    return "UnknownRecord"


def get_type(obj: Any) -> str:
    """Return the type of the Object as 'str'."""
    return str(type(obj))


def has_field(r: Record, field: str) -> bool:
    """Check if field exists on Record object.

    Args:
        r: Record to match on.
        field_name: Field name

    Returns:
        (bool): True if field exists, otherwise False

    """
    return field in r._desc.fields


def field_regex(r: Record, fields: list[str], regex: str) -> bool:
    """Check a regex against fields of a Record object.

    Args:
        r: The record to match on.
        fields: The fields in the Record to match.
        regex: The regex pattern to search for.

    Returns:
        (bool): True or False

    """
    s_pattern = re.compile(regex)
    for field in fields:
        fvalue = getattr(r, field, NONE_OBJECT)
        if fvalue is NONE_OBJECT:
            continue

        match = re.search(s_pattern, fvalue)
        if match is not None:
            return True
    return False


def field_equals(r: Record, fields: list[str], strings: list[str], nocase: bool = True) -> bool:
    """Check for exact string matches on fields of a Record object.

    Args:
        r: The record to match on.
        fields: The fields in the Record to match.
        strings: The strings to search for.
        nocase: Should the matching be case insensitive.

    Returns:
        (bool): True or False

    """
    strings_to_check = [lower(s) for s in strings] if nocase else strings

    for field in fields:
        fvalue = getattr(r, field, NONE_OBJECT)
        if fvalue is NONE_OBJECT:
            continue
        if nocase:
            fvalue = lower(fvalue)
        for s in strings_to_check:
            if s == fvalue:
                return True
    return False


def field_contains(
    r: Record, fields: list[str], strings: list[str], nocase: bool = True, word_boundary: bool = False
) -> bool:
    """Check if the string matches on fields of a Record object.

    Only supports strings for now and partial matches using the __contains__ operator.

    * `fields` is a list of field names to check
    * `strings` is a list of strings to check on the fields
    * `word_boundary` is a boolean. True if matching required only word boundary matches.
    * Non existing fields on the Record object are skipped.
    * Defaults to case-insensitive matching, use `nocase=False` if you want to be case sensitive.
    """
    strings_to_check = [lower(s) for s in strings] if nocase else strings

    for field in fields:
        fvalue = getattr(r, field, NONE_OBJECT)
        if fvalue is NONE_OBJECT:
            continue
        if nocase:
            fvalue = lower(fvalue)
        for s in strings_to_check:
            if word_boundary is False:
                if s in fvalue:
                    return True
            else:
                if fvalue is None:
                    if s is None:
                        return True
                    continue

                if not isinstance(fvalue, str):
                    continue

                s_pattern = f"\\b{re.escape(s)}\\b"
                match = re.search(s_pattern, fvalue)
                if match is not None:
                    return True
    return False


# Function whitelist that are allowed in selectors
FUNCTION_WHITELIST = [
    lower,
    upper,
    name,
    names,
    get_type,
    field_contains,
    field_equals,
    field_regex,
    has_field,
]


def resolve_attr_path(node: ast.Call) -> str:
    """Resolve a node attribute to full path, eg: net.ipv4.Subnet."""
    x = node.func
    attr_path = []
    while isinstance(x, ast.Attribute):
        attr_path.append(x.attr)
        x = x.value
    if isinstance(x, ast.Name):
        attr_path.append(x.id)
    return ".".join(reversed(attr_path))


class SelectorResult:
    def __init__(
        self, expression_str: str, match_result: Any, backtrace: list[tuple[int, Any]], referenced_fields: list
    ):
        self.expresssion_str = expression_str
        self.result = match_result
        self.backtrace_info = backtrace
        self.referenced_fields = referenced_fields

    def backtrace(self) -> str:
        result = ""
        max_source_line_length = len(self.expresssion_str)
        for row in self.backtrace_info[::-1]:
            result += f"{row[0].rstrip().ljust(max_source_line_length + 15)}-> {row[1]}\n"
        return result


class Selector:
    VERBOSITY_ALL = 1
    VERBOSITY_BRANCHES = 2
    VERBOSITY_NONE = 3

    def __init__(self, expression: str):
        expression = expression or "True"
        self.expression_str = expression
        self.expression = compile(
            source=expression,
            filename="<code>",
            mode="eval",
            flags=ast.PyCF_ONLY_AST | __future__.unicode_literals.compiler_flag,
        )
        self.matcher = None

    def __str__(self) -> str:
        return self.expression_str

    def __repr__(self) -> str:
        return f"Selector({self.expression_str!r})"

    def __contains__(self, record: Record) -> bool:
        return self.match(record)

    def explain_selector(self, record: Record, verbosity: int = VERBOSITY_ALL) -> SelectorResult:
        matcher = RecordContextMatcher(self.expression, self.expression_str, backtrace_verbosity=verbosity)
        match_result = matcher.matches(record)
        backtrace_info = matcher.selector_backtrace
        if not HAVE_ASTOR:
            backtrace_info.append(("WARNING: astor module not installed, trace not available", False))
        return SelectorResult(self.expression_str, match_result, backtrace_info, [])

    def match(self, record: Record) -> bool:
        if not self.matcher:
            self.matcher = RecordContextMatcher(self.expression, self.expression_str)

        return self.matcher.matches(record)


class WrappedRecord:
    """WrappedRecord wraps a Record but will return a NoneObject for non existing attributes."""

    __slots__ = ("record",)

    def __init__(self, record: Record):
        self.record = record

    def __getattr__(self, k: str) -> Any:
        return getattr(self.record, k, NONE_OBJECT)

    def __str__(self) -> str:
        return str(self.record)

    def __repr__(self) -> str:
        return repr(self.record)


class CompiledSelector:
    """CompiledSelector is faster than Selector but unsafe if you don't trust the query."""

    def __init__(self, expression: str):
        self.expression = expression or None
        self.code = None
        self.ns = {func.__name__: func for func in FUNCTION_WHITELIST}
        self.ns["net"] = net

        if expression:
            self.code = compile(
                source=expression,
                filename="<code>",
                mode="eval",
                flags=__future__.unicode_literals.compiler_flag,
            )

    def __str__(self) -> str:
        return self.expression

    def __repr__(self) -> str:
        return f"CompiledSelector({self.expression!r})"

    def __contains__(self, record: Record) -> bool:
        return self.match(record)

    def match(self, record: Record) -> bool:
        if self.code is None:
            return True
        ns = self.ns.copy()
        ns.update(
            {
                "r": WrappedRecord(record),
                "Type": TypeMatcher(record),
            }
        )
        return eval(self.code, ns)


class TypeMatcher:
    """
    Helper to get and check fields of a certain type.

    Types can be selected using `Type.<typename>`. Attributes can be selected
    using `Type.<typename>.<attribute>`.

    For example `Type.uri.filename` will retrieve all the filenames from all
    uri's in a record.

    These selectors can also still be used in other helper functions, as
    they will unwrap to resulting fieldnames. So for example, you can still
    do `field_contains(r, Type.string, ['something'])`, which will check
    all `string` fields.

    Membership tests also work. `'something' in Type.string` will perform
    a membership test in each string value and return True if there are any.

    Reverse membership tests are trickier, and only work with a non-compiled
    Selector. For example, `Type.net.ipv4.Address in net.ipv4.Subnet('10.0.0.0/8')`
    requires the TypeMatcher to unroll its values, which is only possible
    when overriding this behaviour.
    """

    def __init__(self, rec: Record):
        self._rec = rec

    def __getattr__(self, attr: str) -> TypeMatcherInstance | NoneObject:
        if attr in WHITELIST_TREE:
            return TypeMatcherInstance(self._rec, [attr])

        return NONE_OBJECT


class TypeMatcherInstance:
    def __init__(self, rec: Record, ftypeparts: list[str] | None = None, attrs: list[str] | None = None):
        self._rec = rec
        self._ftypeparts = ftypeparts or []
        self._attrs = attrs or []

        self._ftype = None
        self._ftypetree = WHITELIST_TREE
        for p in ftypeparts:
            self._ftypetree = self._ftypetree[p]

        if self._ftypetree is True:
            self._ftype = ".".join(ftypeparts)

    def __getattr__(self, attr: str) -> TypeMatcherInstance | NoneObject:
        if not self._ftype:
            if attr not in self._ftypetree:
                return NONE_OBJECT

            ftypeparts = [*self._ftypeparts, attr]
            return TypeMatcherInstance(self._rec, ftypeparts)
        if not attr.startswith("_"):
            attrs = [*self._attrs, attr]
            return TypeMatcherInstance(self._rec, self._ftypeparts, attrs)

        return NONE_OBJECT

    def __iter__(self) -> Iterator[str]:
        return self._fields()

    def _fields(self) -> Iterator[str]:
        for f in self._rec._desc.getfields(self._ftype):
            yield f.name

    def _values(self) -> Iterator[Any]:
        for f in self._fields():
            obj = getattr(self._rec, f, NONE_OBJECT)
            for a in self._attrs:
                obj = getattr(obj, a, NONE_OBJECT)

            if obj is NONE_OBJECT:
                continue

            yield obj

    def _subrecords(self) -> Iterator[Record]:
        """Return all fields that are records (records in records).

        Returns: list of records
        """
        fields = self._rec._desc.getfields("record")
        for f in fields:
            r = getattr(self._rec, f.name)
            if r is not None:
                yield r

        fields = self._rec._desc.getfields("record[]")
        for f in fields:
            records = getattr(self._rec, f.name)
            if records is not None:
                yield from records

    def _op(self, op: Callable[[object, object], bool], other: object) -> bool:
        for v in self._values():
            if op(v, other):
                return True

        subrecords = self._subrecords()
        for record in subrecords:
            type_matcher = TypeMatcherInstance(record, self._ftypeparts, self._attrs)
            if type_matcher._op(op, other):
                return True

        return False

    def __eq__(self, other: object) -> bool:
        return self._op(operator.eq, other)

    def __ne__(self, other: object) -> bool:
        return self._op(operator.ne, other)

    def __lt__(self, other: object) -> bool:
        return self._op(operator.lt, other)

    def __gt__(self, other: object) -> bool:
        return self._op(operator.gt, other)

    def __lte__(self, other: object) -> bool:
        return self._op(operator.le, other)

    def __gte__(self, other: object) -> bool:
        return self._op(operator.ge, other)

    def __noteq__(self, other: object) -> bool:
        return self._op(operator.ne, other)

    def __contains__(self, other: object) -> bool:
        return self._op(operator.contains, other)


class RecordContextMatcher:
    def __init__(self, expr: ast.Expression, expr_str: str, backtrace_verbosity: int = Selector.VERBOSITY_NONE):
        self.expression = expr
        self.expression_str = expr_str
        self.selector_backtrace = []
        self.selector_backtrace_verbosity = backtrace_verbosity
        self.data = {}
        self.rec = None

    def matches(self, rec: Record) -> bool:
        self.selector_backtrace = []
        self.data = {
            "None": None,
            "True": True,
            "False": False,
            "str": str,
            "repr": repr,
            "fields": rec._desc.getfields,
            "any": any,
            "all": all,
        }

        # Add whitelisted functions to global dict
        self.data.update({func.__name__: func for func in FUNCTION_WHITELIST})

        self.data["r"] = rec
        self.rec = rec

        # Type matcher
        self.data["Type"] = TypeMatcher(rec)

        return self.eval(self.expression.body)

    def eval(self, node: ast.expr) -> Any:
        r = self._eval(node)
        verbosity = self.selector_backtrace_verbosity
        log_trace = (verbosity == Selector.VERBOSITY_ALL) or (
            verbosity == Selector.VERBOSITY_BRANCHES and isinstance(node, (ast.Compare, ast.BoolOp))
        )
        if log_trace and HAVE_ASTOR:
            source_line = astor.to_source(node)
            self.selector_backtrace.append((source_line, r))
        return r

    def _eval(self, node: ast.expr) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return list(map(self.eval, node.elts))
        if isinstance(node, ast.Tuple):
            return tuple(map(self.eval, node.elts))
        if isinstance(node, ast.Name):
            if node.id not in self.data:
                return getattr(dynamic_fieldtype, node.id)

            return self.data[node.id]
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                raise InvalidOperation(f"Selector {self.expression_str!r} contains invalid attribute: {node.attr!r}")

            obj = self.eval(node.value)

            return getattr(obj, node.attr, NONE_OBJECT)
        if isinstance(node, ast.BoolOp):
            values = []
            for expr in node.values:
                try:
                    value = self.eval(expr)
                except TypeError as e:
                    if "NoneType" in str(e):
                        value = False
                    else:
                        raise
                value = bool(value)
                values.append(value)
            result = values.pop(0)
            for value in values:
                result = AST_OPERATORS[type(node.op)](result, value)
            return result
        if isinstance(node, ast.BinOp):
            left = self.eval(node.left)
            right = self.eval(node.right)
            if isinstance(left, NoneObject) or isinstance(right, NoneObject):
                return False
            return AST_OPERATORS[type(node.op)](left, right)
        if isinstance(node, ast.UnaryOp):
            return AST_OPERATORS[type(node.op)](self.eval(node.operand))
        if isinstance(node, ast.Compare):
            left = self.eval(node.left)
            right = self.eval(node.comparators[0])

            # print [AST_COMPARATORS[type(node.ops[0])](getattr(self.rec, l.name), right) for l in left]
            # return [AST_COMPARATORS[type(node.ops[0])](getattr(self.rec, l.name), right) for l in left]

            comptype = type(node.ops[0])
            comp = AST_COMPARATORS[comptype]

            # Special case for __contains__, where we need to first unwrap all values matching the Type query
            if comptype in (ast.In, ast.NotIn) and isinstance(left, TypeMatcherInstance):
                return any(comp(v, right) for v in left._values())
            return comp(left, right)
        if isinstance(node, ast.Call):
            if not isinstance(node.func, (ast.Attribute, ast.Name)):
                raise InvalidOperation("Error, only ast.Attribute or ast.Name are expected")

            func_name = resolve_attr_path(node)
            if not (callable(self.data.get(func_name)) or func_name in WHITELIST):
                raise InvalidOperation(
                    f"Call '{func_name}' not allowed. No calls other then whitelisted 'global' calls allowed!"
                )

            func = self.eval(node.func)

            args = list(map(self.eval, node.args))
            kwargs = {kw.arg: self.eval(kw.value) for kw in node.keywords}

            return func(*args, **kwargs)

        if isinstance(node, ast.comprehension):
            return self.eval(node.iter)

        if isinstance(node, ast.GeneratorExp):

            def recursive_generator(gens: list[ast.comprehension]) -> Iterator[Any]:
                """
                Yield all the values in the most deepest generator.

                Example:
                [ord(c) for line in file for c in line]
                This function would yield all c values for this expression

                Args:
                    gens: A list of generator/ comprehension objects

                Returns:
                    Generator
                """
                gens = list(gens)
                gen = gens.pop()
                loop_index_var_name = gen.target.id
                resolved_gen = self.eval(gen)
                if resolved_gen is not NONE_OBJECT:
                    for val in resolved_gen:
                        self.data[loop_index_var_name] = val
                        if len(gens) > 0:
                            yield from recursive_generator(gens)
                        else:
                            yield val

            def generator_expr() -> Iterator[Any]:
                """
                Embedded generator logic for ast.GeneratorExp.

                A function can't yield and return so we write nested generator function and return that.

                Returns:
                    yields evaluated generator expression values

                """
                for gen in node.generators:
                    if gen.target.id in self.data:
                        raise InvalidOperation(f"Generator variable '{gen.target.id}' overwrites existing variable!")
                values = recursive_generator(node.generators[::-1])
                for _ in values:
                    result = self.eval(node.elt)
                    yield result

            return generator_expr()

        raise TypeError(node)


def make_selector(selector: str | Selector | None, force_compiled: bool = False) -> Selector | CompiledSelector | None:
    """Return a Selector object (either CompiledSelector or Selector)."""
    ret = selector
    if not selector:
        ret = None
    elif isinstance(selector, str):
        ret = CompiledSelector(selector) if force_compiled else Selector(selector)
    elif isinstance(selector, Selector) and force_compiled:
        ret = CompiledSelector(selector.expression_str)
    return ret
