# SPDX-License-Identifier: Apache-2.0
"""Safe evaluation of the small condition language used in config (risk model, applicability).

Configuration is reviewed by humans but must never be able to execute code (ADR-011, threat T-12), so this is
NOT Python `eval`. Expressions are parsed with `ast` and only an allowlisted subset is accepted:

    vuln.in_cisa_kev and app.exposure in ['internet_public', 'internet_authenticated']
    finding.requires_auth == false
    size(capabilities.oauth_oidc) > 0

* names resolve only to roots supplied in the context (plus true / false / null)
* attribute access walks dictionaries; it never touches Python object attributes
* the only callable is `size()`
* a missing attribute evaluates to null; ordering comparisons with null are false
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

MAX_LENGTH = 500
MAX_DEPTH = 12
LITERALS: dict[str, Any] = {"true": True, "false": False, "null": None}
FUNCTIONS: dict[str, Callable[[Any], Any]] = {"size": lambda v: 0 if v is None else len(v)}


class ExpressionError(ValueError):
    """Raised when an expression is malformed or uses a construct outside the allowlist."""


_COMPARATORS: dict[type[ast.cmpop], Callable[[Any, Any], bool]] = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
    ast.In: lambda a, b: b is not None and a in b,
    ast.NotIn: lambda a, b: b is None or a not in b,
}
_ORDERING = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


@dataclass(frozen=True)
class Expression:
    source: str
    tree: ast.expr
    roots: frozenset[str]

    def evaluate(self, context: Mapping[str, Any]) -> Any:
        return _eval(self.tree, context)

    def test(self, context: Mapping[str, Any]) -> bool:
        return bool(self.evaluate(context))


def compile_expression(source: str, allowed_roots: frozenset[str] | set[str] | None = None) -> Expression:
    """Parse and validate. `allowed_roots`, when given, rejects references to unknown context roots."""
    if not isinstance(source, str) or not source.strip():
        raise ExpressionError("expression must be a non-empty string")
    if len(source) > MAX_LENGTH:
        raise ExpressionError(f"expression longer than {MAX_LENGTH} characters")
    try:
        module = ast.parse(source.strip(), mode="eval")
    except SyntaxError as e:
        raise ExpressionError(f"syntax error: {e.msg}") from e
    roots: set[str] = set()
    _validate(module.body, roots, depth=0)
    if allowed_roots is not None:
        unknown = roots - set(allowed_roots)
        if unknown:
            raise ExpressionError(f"unknown names: {sorted(unknown)}")
    return Expression(source=source, tree=module.body, roots=frozenset(roots))


def _validate(node: ast.AST, roots: set[str], depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ExpressionError("expression nested too deeply")
    match node:
        case ast.BoolOp(values=values):
            for v in values:
                _validate(v, roots, depth + 1)
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            _validate(operand, roots, depth + 1)
        case ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=int() | float())):
            pass
        case ast.Compare(left=left, ops=ops, comparators=comparators):
            if any(type(op) not in _COMPARATORS for op in ops):
                raise ExpressionError("unsupported comparison operator")
            for n in (left, *comparators):
                _validate(n, roots, depth + 1)
        case ast.Name(id=name):
            if name.startswith("_"):
                raise ExpressionError(f"name not allowed: {name}")
            if name not in LITERALS:
                roots.add(name)
        case ast.Attribute(value=value, attr=attr):
            if attr.startswith("_"):
                raise ExpressionError(f"attribute not allowed: {attr}")
            if not isinstance(value, ast.Name | ast.Attribute):
                raise ExpressionError("attribute access only on names")
            _validate(value, roots, depth + 1)
        case ast.Constant(value=value):
            if not isinstance(value, str | int | float | bool | type(None)):
                raise ExpressionError("unsupported literal")
        case ast.List(elts=elts) | ast.Tuple(elts=elts):
            for e in elts:
                _validate(e, roots, depth + 1)
        case ast.Call(func=ast.Name(id=fn), args=args, keywords=[]) if fn in FUNCTIONS and len(args) == 1:
            _validate(args[0], roots, depth + 1)
        case _:
            raise ExpressionError(f"construct not allowed: {type(node).__name__}")


def _eval(node: ast.expr, ctx: Mapping[str, Any]) -> Any:
    match node:
        case ast.BoolOp(op=ast.And(), values=values):
            return all(_eval(v, ctx) for v in values)
        case ast.BoolOp(op=ast.Or(), values=values):
            return any(_eval(v, ctx) for v in values)
        case ast.UnaryOp(op=ast.Not(), operand=operand):
            return not _eval(operand, ctx)
        case ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=int() | float() as v)):
            return -v
        case ast.Compare(left=left, ops=ops, comparators=comparators):
            return _compare(_eval(left, ctx), ops, [_eval(c, ctx) for c in comparators])
        case ast.Name(id=name):
            return LITERALS[name] if name in LITERALS else ctx.get(name)
        case ast.Attribute(value=value, attr=attr):
            base = _eval(value, ctx)
            return base.get(attr) if isinstance(base, Mapping) else None
        case ast.Constant(value=value):
            return value
        case ast.List(elts=elts) | ast.Tuple(elts=elts):
            return [_eval(e, ctx) for e in elts]
        case ast.Call(func=ast.Name(id=fn), args=[arg]):
            return FUNCTIONS[fn](_eval(arg, ctx))
    raise ExpressionError(f"cannot evaluate {type(node).__name__}")  # unreachable after validation


def _compare(left: Any, ops: list[ast.cmpop], rights: list[Any]) -> bool:
    for op, right in zip(ops, rights, strict=True):
        if isinstance(op, _ORDERING) and (left is None or right is None):
            return False
        try:
            if not _COMPARATORS[type(op)](left, right):
                return False
        except TypeError:
            return False
        left = right
    return True
