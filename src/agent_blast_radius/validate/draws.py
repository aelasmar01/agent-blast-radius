"""Stratified, boundary-weighted draw generation.

Uniform draws from ungranted actions are trivially denied and inflate the matrix. The
deny-expected strata here are near-misses, because that is where a resolver breaks:
right action / wrong resource, right action and resource / failing condition, actions
just outside a wildcard boundary, actions under an explicit Deny, and — for NotAction
policies — actions inside the excluded set, where the resolver has declared itself
unable to answer.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from dataclasses import dataclass, field

from ..iam import actions as action_db
from ..iam import arn as arn_util
from ..iam import conditions as cond_util
from ..iam.resolver import Resolution, role_documents
from ..ir import Capability, Condition, Role

Decision = str  # "allow" | "allow-flagged" | "deny" | "unsupported"

STRATA_ALLOW = ("allow-unconditional", "allow-conditioned", "allow-flagged")
STRATA_DENY = (
    "wrong-resource",
    "condition-fail",
    "wildcard-boundary",
    "explicit-deny",
    "notaction-excluded",
    "uniform",
)


@dataclass(frozen=True, slots=True)
class Draw:
    action: str
    resource: str | None
    context: tuple[tuple[str, str], ...]
    stratum: str
    expected: Decision
    note: str = ""

    @property
    def context_dict(self) -> dict[str, str]:
        return dict(self.context)


@dataclass
class DrawPlan:
    draws: list[Draw] = field(default_factory=list)

    def by_stratum(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for d in self.draws:
            out[d.stratum] = out.get(d.stratum, 0) + 1
        return out


# --- resolver-side decision for a draw ------------------------------------------------


def resolver_decision(
    resolution: Resolution, action: str, resource: str | None, context: dict[str, str]
) -> Decision:
    """What the resolver claims for this (action, resource, context).

    ``resource=None`` mirrors a simulation with no ``ResourceArns``, which AWS evaluates
    against ``*``; only a capability on ``*`` covers that.
    """
    best: Decision = "deny"
    for cap in resolution.capabilities:
        if cap.action.lower() != action.lower():
            continue
        if resource is None:
            if cap.resource != "*":
                continue
        elif not arn_util.matches(cap.resource, resource):
            continue
        if cap.conditions and not cond_util.evaluate(cap.conditions, context):
            continue
        if not cap.residue.is_clean:
            best = "allow-flagged" if best == "deny" else best
            continue
        return "allow"
    if best == "deny" and any(
        u.kind in ("NotAction", "NotResource") for u in resolution.unsupported
    ):
        return "unsupported"
    return best


# --- helpers ----------------------------------------------------------------------------


def concretize(pattern: str) -> str | None:
    """A concrete ARN matching a resource pattern, or None for ``*``."""
    if pattern == "*":
        return None
    return pattern.replace("*", "x").replace("?", "a")


def _satisfying_context(conditions: tuple[Condition, ...]) -> tuple[tuple[str, str], ...]:
    ctx: list[tuple[str, str]] = []
    for c in conditions:
        value = c.values[0]
        if c.operator in ("StringLike", "ArnLike"):
            value = value.replace("*", "x").replace("?", "a")
        ctx.append((c.key, value))
    return tuple(ctx)


def _failing_context(conditions: tuple[Condition, ...]) -> tuple[tuple[str, str], ...] | None:
    ctx = list(_satisfying_context(conditions))
    if not ctx:
        return None
    key, value = ctx[0]
    op = conditions[0].operator
    if op == "Bool":
        bad = "false" if value.lower() == "true" else "true"
    elif op == "ArnLike":
        bad = "arn:aws:iam::999999999999:role/definitely-not-it"
    else:
        bad = value + "-not-it"
    ctx[0] = (key, bad)
    return tuple(ctx)


def _mutate_resource(pattern: str, all_patterns: Iterable[str]) -> str | None:
    """A concrete ARN close to ``pattern`` that no pattern in ``all_patterns`` matches."""
    concrete = concretize(pattern)
    if concrete is None or not arn_util.is_arn(concrete):
        return None
    a = arn_util.Arn.parse(concrete)
    p = arn_util.Arn.parse(pattern)
    candidates: list[str] = []
    if p.account and "*" not in p.account:
        candidates.append(f"arn:{a.partition}:{a.service}:{a.region}:999999999999:{a.resource}")
    if p.region and "*" not in p.region:
        candidates.append(f"arn:{a.partition}:{a.service}:eu-west-3:{a.account}:{a.resource}")
    literal = p.resource.split("*", 1)[0].split("?", 1)[0]
    if literal:
        # Change the last literal character before the wildcard: one segment off.
        mutated = literal[:-1] + ("z" if literal[-1] != "z" else "y") + a.resource[len(literal) :]
        candidates.append(f"arn:{a.partition}:{a.service}:{a.region}:{a.account}:{mutated}")
    for cand in candidates:
        if not any(arn_util.matches(pp, cand) for pp in all_patterns):
            return cand
    return None


def _wildcard_siblings(action: str, granted: frozenset[str]) -> list[str]:
    """Known actions in the same service, sharing a prefix with ``action``, not granted."""
    service, _, name = action.partition(":")
    prefix = name[:3]
    same_service = [a for a in action_db.expand(f"{service}:*") if a not in granted]
    close = [a for a in same_service if a.split(":", 1)[1][:3].lower() == prefix.lower()]
    return close or same_service


# --- plan --------------------------------------------------------------------------------


def plan_draws(
    role: Role, resolution: Resolution, *, per_policy: int = 40, seed: int = 0
) -> DrawPlan:
    rng = random.Random(f"{seed}:{role.name}")
    half = per_policy // 2
    plan = DrawPlan()
    # A policy with a skipped NotAction/NotResource statement makes the resolver unable
    # to claim "deny" about anything it did not positively allow. Deny-expected draws on
    # such a policy expect `unsupported`, not `deny` — the resolver is declining, not
    # answering. AWS may still say allowed or denied; that spread is the cost of the
    # refusal and is exactly what the matrix's `unsupported` row measures.
    refuses = any(u.kind in ("NotAction", "NotResource") for u in resolution.unsupported)
    deny_expected: Decision = "unsupported" if refuses else "deny"
    caps = sorted(resolution.capabilities, key=lambda c: (c.action, c.resource))
    granted = frozenset(c.action for c in caps)
    patterns_for: dict[str, set[str]] = {}
    for c in caps:
        patterns_for.setdefault(c.action, set()).add(c.resource)

    # ---- allow-expected ---------------------------------------------------------------
    unconditional = [c for c in caps if c.is_unconditional]
    conditioned = [c for c in caps if c.conditions and c.residue.is_clean]
    flagged = [c for c in caps if not c.residue.is_clean]

    def weight(c: Capability) -> int:
        # Prefer scoped resources and conditioned grants: the non-trivial cases.
        w = 1
        if c.resource != "*":
            w += 2
        if c.conditions:
            w += 1
        return w

    def sample(pool: list[Capability], k: int) -> list[Capability]:
        if not pool or k <= 0:
            return []
        weights = [weight(c) for c in pool]
        picked: list[Capability] = []
        pool = list(pool)
        while pool and len(picked) < k:
            c = rng.choices(pool, weights=weights, k=1)[0]
            i = pool.index(c)
            pool.pop(i)
            weights.pop(i)
            picked.append(c)
        return picked

    n_flagged = min(len(flagged), max(2, half // 8))
    n_cond = min(len(conditioned), max(2, half // 4))
    n_uncond = half - n_flagged - n_cond
    for c in sample(unconditional, n_uncond):
        plan.draws.append(
            Draw(c.action, concretize(c.resource), (), "allow-unconditional", "allow")
        )
    for c in sample(conditioned, n_cond):
        plan.draws.append(
            Draw(
                c.action,
                concretize(c.resource),
                _satisfying_context(c.conditions),
                "allow-conditioned",
                "allow",
            )
        )
    for c in sample(flagged, n_flagged):
        plan.draws.append(
            Draw(
                c.action,
                concretize(c.resource),
                _satisfying_context(c.conditions),
                "allow-flagged",
                "allow-flagged",
                note=",".join(c.residue.unmodeled_keys),
            )
        )

    # ---- deny-expected, boundary-weighted ------------------------------------------------
    deny: list[Draw] = []
    scoped = [c for c in caps if c.resource != "*"]
    for c in sample(scoped, half // 4 or 1):
        mutated = _mutate_resource(c.resource, patterns_for[c.action])
        if mutated:
            deny.append(
                Draw(
                    c.action,
                    mutated,
                    _satisfying_context(c.conditions),
                    "wrong-resource",
                    deny_expected,
                )
            )
    for c in sample(conditioned, half // 5 or 1):
        ctx = _failing_context(c.conditions)
        # Breaking one statement's condition only denies the action if that statement is
        # the sole grant. In a 40-statement managed policy the same action is often
        # granted several times over, and the resolver is right to still allow it.
        if ctx and _sole_grant(caps, c, concretize(c.resource), dict(ctx)):
            deny.append(
                Draw(c.action, concretize(c.resource), ctx, "condition-fail", deny_expected)
            )
    # One boundary probe per granted service, so iam:* policies don't crowd out the rest.
    by_service: dict[str, list[Capability]] = {}
    for c in caps:
        by_service.setdefault(c.service, []).append(c)
    services = sorted(by_service)
    rng.shuffle(services)
    boundary = 0
    for service in services:
        if boundary >= (half // 4 or 1):
            break
        c = rng.choice(by_service[service])
        siblings = _wildcard_siblings(c.action, granted)
        if siblings:
            deny.append(
                Draw(rng.choice(sorted(siblings)), None, (), "wildcard-boundary", deny_expected)
            )
            boundary += 1
    denied_actions = sorted(_explicitly_denied(role, granted))
    for a in rng.sample(denied_actions, min(len(denied_actions), half // 5 or 1)):
        deny.append(Draw(a, None, (), "explicit-deny", deny_expected))
    # An excluded action that some *other* statement allows anyway is not a refusal case;
    # the resolver answers it positively and is right to. Draw only from the genuinely
    # unanswerable remainder.
    for a in sorted(_notaction_excluded(role) - granted)[: half // 5 or 1]:
        deny.append(Draw(a, None, (), "notaction-excluded", "unsupported"))
    # Uniform tail: sanity floor.
    universe = sorted(action_db.expand("*") - granted)
    for a in rng.sample(universe, min(4, len(universe))):
        deny.append(Draw(a, None, (), "uniform", deny_expected))

    plan.draws.extend(deny[:half] if len(deny) > half else deny)
    return plan


def _explicitly_denied(role: Role, granted: frozenset[str]) -> set[str]:
    out: set[str] = set()
    docs, _ = role_documents(role)
    for doc in docs:
        for s in doc.statements:
            if s.effect.value == "Deny" and not s.conditions:
                for pattern in s.actions:
                    out |= set(action_db.expand(pattern))
    return out - granted


def _notaction_excluded(role: Role) -> set[str]:
    """Actions inside a NotAction exclusion, i.e. ones the skipped statement would grant."""
    out: set[str] = set()
    docs, _ = role_documents(role)
    for doc in docs:
        for s in doc.statements:
            for pattern in s.not_actions:
                out |= set(action_db.expand(pattern))
    return out


def _sole_grant(
    capabilities: list[Capability],
    capability: Capability,
    resource: str | None,
    context: dict[str, str],
) -> bool:
    """Is ``capability`` the only one granting its action on ``resource`` in this context?

    Used to keep ``condition-fail`` draws honest: breaking one statement's condition is
    only a denial when no other statement grants the same thing.
    """
    for other in capabilities:
        if other is capability or other.action.lower() != capability.action.lower():
            continue
        if resource is None:
            if other.resource != "*":
                continue
        elif not arn_util.matches(other.resource, resource):
            continue
        if other.conditions and not cond_util.evaluate(other.conditions, context):
            continue
        return False
    return True
