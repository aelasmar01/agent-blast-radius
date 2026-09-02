"""Condition modeling.

Four operators are modeled: ``StringEquals``, ``StringLike``, ``ArnLike``, ``Bool``.
Everything else — ``IfExists`` variants, ``ForAnyValue``/``ForAllValues`` set operators,
``StringEqualsIgnoreCase``, numeric and date operators, ``Null`` — is recorded as residue.
A capability with residue is reported as *unconstrained but flagged*: the conservative
direction, and the one that can be defended out loud.

:func:`evaluate` is used where a request context exists (the differential harness and
Deny evaluation), never to silently narrow an Allow at analysis time.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping

from ..ir import Condition, ConditionResidue
from .arn import matches as arn_matches

MODELED = frozenset({"StringEquals", "StringLike", "ArnLike", "Bool"})


def split(
    raw: tuple[tuple[str, str, tuple[str, ...]], ...],
) -> tuple[tuple[Condition, ...], ConditionResidue]:
    """Partition a statement's condition clauses into modeled conditions and residue."""
    modeled: list[Condition] = []
    residue: list[str] = []
    for operator, key, values in raw:
        if operator in MODELED:
            modeled.append(Condition(operator, key, values))
        else:
            residue.append(f"{operator}:{key}")
    return tuple(modeled), ConditionResidue(tuple(sorted(residue)))


def _holds(condition: Condition, value: str | None) -> bool:
    # A missing key fails every non-IfExists operator. That is IAM's rule, not ours.
    if value is None:
        return False
    op = condition.operator
    if op == "StringEquals":
        return value in condition.values
    if op == "StringLike":
        return any(fnmatch.fnmatchcase(value, pattern) for pattern in condition.values)
    if op == "ArnLike":
        return any(arn_matches(pattern, value) for pattern in condition.values)
    if op == "Bool":
        return value.lower() in {v.lower() for v in condition.values}
    raise ValueError(f"operator {op!r} is not modeled")


def evaluate(conditions: tuple[Condition, ...], context: Mapping[str, str]) -> bool:
    """Do all modeled conditions hold in this request context? Keys are case-insensitive."""
    lowered = {k.lower(): v for k, v in context.items()}
    return all(_holds(c, lowered.get(c.key.lower())) for c in conditions)


def restricts(conditions: tuple[Condition, ...], key: str) -> tuple[str, ...] | None:
    """The allowed values a modeled condition places on ``key``, or None if unconstrained.

    The rule engine uses this to ask, for example, whether ``iam:PassedToService`` on a
    PassRole capability admits ``lambda.amazonaws.com``.
    """
    for c in conditions:
        if c.key.lower() == key.lower() and c.operator in {"StringEquals", "StringLike"}:
            return c.values
    return None


def admits(conditions: tuple[Condition, ...], key: str, value: str) -> bool:
    """Would a condition on ``key`` allow ``value``? Unconstrained keys admit everything."""
    allowed = restricts(conditions, key)
    if allowed is None:
        return True
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in allowed)
