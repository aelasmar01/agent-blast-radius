"""Offline pre-flight: check the resolver against each draw's own expectation.

**This is a lint pass, not validation.** It shares every assumption the resolver makes
about IAM, so it cannot find a case where the semantics were misunderstood — which is
exactly the class of bug the live ``iam:SimulateCustomPolicy`` run exists to catch.
Passing pre-flight is not evidence of correctness. Only the confusion matrix is.

What it *is* good for: the boundary strata build their expectation from the policy
structure, in code that never consults :func:`resolver_decision` —
``_mutate_resource`` constructs an ARN no granted pattern matches, ``_failing_context``
flips a modeled condition, ``_wildcard_siblings`` picks actions outside the granted set,
``_explicitly_denied`` reads Deny statements. When the resolver disagrees with one of
those, something is wrong today, offline, for free.

The allow-expected strata are drawn from the resolver's own output, so agreement there
is circular by construction and is reported separately and discounted.
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field

from ..iam.resolver import resolve_role
from .corpus import CorpusEntry
from .draws import STRATA_ALLOW, Draw, resolver_decision
from .run import build_plans

#: Strata whose expectation is derived independently of the resolver's answer path.
INDEPENDENT_STRATA = frozenset(
    {"wrong-resource", "condition-fail", "wildcard-boundary", "explicit-deny", "notaction-excluded"}
)
#: Drawn from the resolver's own output: agreement proves nothing.
CIRCULAR_STRATA = frozenset(STRATA_ALLOW)


@dataclass(frozen=True, slots=True)
class Mismatch:
    policy: str
    group: str
    draw: Draw
    expected: str
    actual: str

    @property
    def is_independent(self) -> bool:
        return self.draw.stratum in INDEPENDENT_STRATA

    def __str__(self) -> str:
        ctx = f" ctx={dict(self.draw.context)}" if self.draw.context else ""
        note = f"  ({self.draw.note})" if self.draw.note else ""
        return (
            f"{self.policy} [{self.draw.stratum}] {self.draw.action} "
            f"on {self.draw.resource or '*'}{ctx}: expected {self.expected}, "
            f"resolver said {self.actual}{note}"
        )


@dataclass
class Preflight:
    checked: int = 0
    mismatches: list[Mismatch] = field(default_factory=list)
    by_stratum: Counter = field(default_factory=Counter)

    @property
    def real(self) -> list[Mismatch]:
        """Mismatches on independently-derived expectations. These are bugs."""
        return [m for m in self.mismatches if m.is_independent]

    @property
    def circular(self) -> list[Mismatch]:
        return [m for m in self.mismatches if m.draw.stratum in CIRCULAR_STRATA]

    @property
    def ok(self) -> bool:
        return not self.real


def _equivalent(expected: str, actual: str) -> bool:
    """``allow-flagged`` satisfies an ``allow`` expectation: it is allow, conservatively."""
    if expected == actual:
        return True
    return expected == "allow" and actual == "allow-flagged"


def preflight(entries: list[CorpusEntry], *, per_policy: int = 40, seed: int = 0) -> Preflight:
    result = Preflight()
    for entry, plan in build_plans(entries, per_policy=per_policy, seed=seed):
        resolution = resolve_role(entry.role)
        for draw in plan.draws:
            actual = resolver_decision(resolution, draw.action, draw.resource, draw.context_dict)
            result.checked += 1
            result.by_stratum[draw.stratum] += 1
            if not _equivalent(draw.expected, actual):
                result.mismatches.append(
                    Mismatch(entry.name, entry.group, draw, draw.expected, actual)
                )
    return result


def render(result: Preflight, out=None) -> None:
    out = out or sys.stderr
    print(f"pre-flight: {result.checked} draws checked offline, no AWS calls", file=out)
    strata = ", ".join(f"{k}={v}" for k, v in sorted(result.by_stratum.items()))
    print(f"  strata: {strata}", file=out)
    print("", file=out)

    if result.real:
        print(f"{len(result.real)} MISMATCH(ES) on independently-derived expectations:", file=out)
        for m in result.real:
            print(f"  - {m}", file=out)
        print("", file=out)
    else:
        n = sum(result.by_stratum[s] for s in INDEPENDENT_STRATA)
        print(f"no mismatches on the {n} independently-derived draws", file=out)

    if result.circular:
        print(
            f"{len(result.circular)} mismatch(es) on resolver-derived (circular) draws — "
            "informational only:",
            file=out,
        )
        for m in result.circular:
            print(f"  - {m}", file=out)
        print("", file=out)

    print(
        "This is a lint pass, not validation. It shares the resolver's assumptions about\n"
        "IAM and cannot catch a misunderstanding of the semantics. Passing here is not\n"
        "evidence of correctness — run `validate` against iam:SimulateCustomPolicy for that.",
        file=out,
    )
