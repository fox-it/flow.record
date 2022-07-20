"""
Backport of `inspect.signature` for Python 2.

Based on: https://github.com/python/cpython/blob/3.7/Lib/inspect.py
"""

import inspect
import collections


class _empty:
    pass


class Parameter:
    POSITIONAL_ONLY = 0
    POSITIONAL_OR_KEYWORD = 1
    VAR_POSITIONAL = 2
    KEYWORD_ONLY = 3
    VAR_KEYWORD = 4

    empty = _empty

    def __init__(self, name, kind, default=_empty):
        self.name = name
        self.kind = kind
        self.default = default


class Signature:
    empty = _empty

    def __init__(self, parameters=None):
        self.parameters = parameters


def signature(obj):
    try:
        # Python 3
        return inspect.signature(obj)
    except AttributeError:
        # Python 2
        spec = inspect.getargspec(obj)

        # Create parameter objects which are compatible with python 3 objects
        parameters = collections.OrderedDict()
        for i in range(0, len(spec.args)):
            arg = spec.args[i]
            default = _empty
            if spec.defaults and (len(spec.args) - i <= len(spec.defaults)):
                default = spec.defaults[i - len(spec.args)]
            parameters[arg] = Parameter(name=arg, default=default, kind=Parameter.POSITIONAL_OR_KEYWORD)
        if spec.varargs:
            parameters[spec.varargs] = Parameter(name=spec.varargs, kind=Parameter.VAR_POSITIONAL)
        if spec.keywords:
            parameters[spec.keywords] = Parameter(name=spec.keywords, kind=Parameter.VAR_KEYWORD)

        return Signature(parameters=parameters)
