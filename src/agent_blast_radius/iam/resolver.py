"""Resolve a role's policies into an effective capability set.

Order of operations, which is the part that has to be right:

1. Collect every policy document behind the role: inline identity policies plus attached
   managed policies from the vendored snapshot. An attachment the snapshot doesn't know
   is recorded as ``Unsupported`` — the analysis is incomplete, not wrong.
2. Refuse ``NotAction`` / ``NotResource`` at the statement level. The statement is
   skipped, recorded, and the scan continues. It never raises on the scan path.
3. Expand every Allow into ``(action, resource, conditions)`` triples with provenance.
4. Subtract Denies. A Deny removes an Allow capability only when it is unconditional
   and its resource pattern subsumes the capability's. A conditional Deny, or a
   partial-overlap Deny, cannot be evaluated without a request context, so the
   capability is kept and flagged in its residue — a Deny we cannot prove must never
   produce a false negative.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from ..ir import (
    Capability,
    ConditionResidue,
    Deployment,
    Effect,
    PolicyDocument,
    Provenance,
    Role,
    Statement,
    Unsupported,
)
from . import actions, arn, conditions, managed


@dataclass(frozen=True, slots=True)
class Resolution:
    capabilities: frozenset[Capability]
    unsupported: tuple[Unsupported, ...]

    @property
    def actions(self) -> frozenset[str]:
        return frozenset(c.action for c in self.capabilities)

    def find(self, action: str) -> tuple[Capability, ...]:
        return tuple(c for c in self.capabilities if c.action.lower() == action.lower())


@dataclass(frozen=True, slots=True)
class _Deny:
    actions: frozenset[str]
    resources: tuple[str, ...]
    conditional: bool
    provenance: Provenance


def _documents(role: Role) -> tuple[list[PolicyDocument], list[Unsupported]]:
    docs = list(role.identity_policies)
    unsupported: list[Unsupported] = []
    for policy_arn in role.managed_policy_arns:
        doc = managed.lookup(policy_arn)
        if doc is None:
            unsupported.append(
                Unsupported(
                    "unresolved_managed_policy",
                    role.name,
                    policy_arn,
                    "-",
                    "not in vendored snapshot",
                )
            )
        else:
            docs.append(doc)
    return docs, unsupported


def _expand_statement(
    statement: Statement, role: str, policy: str
) -> tuple[frozenset[str], list[Unsupported]]:
    expanded: set[str] = set()
    unsupported: list[Unsupported] = []
    for pattern in statement.actions:
        hits = actions.expand(pattern)
        if not hits or (not actions.has_wildcard(pattern) and not actions.is_known(pattern)):
            unsupported.append(Unsupported("unknown_action", role, policy, statement.sid, pattern))
        expanded.update(hits)
    return frozenset(expanded), unsupported


def resolve_role(role: Role) -> Resolution:
    docs, unsupported = _documents(role)
    allows: dict[tuple, Capability] = {}
    denies: list[_Deny] = []

    for doc in docs:
        for statement in doc.statements:
            provenance = Provenance(role.name, doc.name, statement.sid)
            negated = statement.uses_negated_construct
            if negated:
                unsupported.append(
                    Unsupported(negated, role.name, doc.name, statement.sid, "statement skipped")
                )
                continue
            expanded, unknown = _expand_statement(statement, role.name, doc.name)
            unsupported.extend(unknown)
            modeled, residue = conditions.split(statement.conditions)

            if statement.effect is Effect.DENY:
                denies.append(
                    _Deny(
                        actions=expanded,
                        resources=statement.resources or ("*",),
                        conditional=bool(modeled) or not residue.is_clean,
                        provenance=provenance,
                    )
                )
                continue

            for action in expanded:
                for resource in statement.resources or ("*",):
                    key = (action, resource, modeled, residue)
                    existing = allows.get(key)
                    allows[key] = Capability(
                        action=action,
                        resource=resource,
                        conditions=modeled,
                        residue=residue,
                        provenance=(existing.provenance if existing else ()) + (provenance,),
                    )

    return Resolution(
        capabilities=frozenset(_apply_denies(allows.values(), denies)),
        unsupported=tuple(unsupported),
    )


def _apply_denies(capabilities, denies: list[_Deny]) -> list[Capability]:
    kept: list[Capability] = []
    for cap in capabilities:
        removed = False
        flags: list[str] = []
        for deny in denies:
            if cap.action not in deny.actions:
                continue
            if deny.conditional:
                # Cannot prove the Deny applies without a request context; keep and flag.
                if any(arn.overlaps(r, cap.resource) for r in deny.resources):
                    flags.append(f"deny-conditional:{deny.provenance}")
                continue
            if any(arn.subsumes(r, cap.resource) for r in deny.resources):
                removed = True
                break
            if any(arn.overlaps(r, cap.resource) for r in deny.resources):
                flags.append(f"deny-partial:{deny.provenance}")
        if removed:
            continue
        if flags:
            cap = Capability(
                action=cap.action,
                resource=cap.resource,
                conditions=cap.conditions,
                residue=cap.residue.merge(ConditionResidue(tuple(flags))),
                provenance=cap.provenance,
            )
        kept.append(cap)
    return kept


def resolve_deployment(deployment: Deployment) -> dict[str, Resolution]:
    """Resolve every role once. Keyed by role name."""
    return {role.name: resolve_role(role) for role in deployment.roles}


def unsupported_by_kind(resolutions: dict[str, Resolution]) -> dict[str, list[Unsupported]]:
    out: dict[str, list[Unsupported]] = defaultdict(list)
    for res in resolutions.values():
        for u in res.unsupported:
            out[u.kind].append(u)
    return dict(out)
