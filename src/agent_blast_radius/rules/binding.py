"""Substitution enumeration and clause checking. See docs/rule-semantics.md."""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ..iam import arn as arn_util
from ..iam import conditions as cond_util
from ..ir import Capability, Deployment, Role
from .loader import VAR, ActionClause, Fact, Rule

Sigma = dict[str, str]  # variable -> role name


@dataclass(frozen=True, slots=True)
class ClauseMatch:
    clause: ActionClause
    capability: Capability

    @property
    def flagged(self) -> bool:
        return not self.capability.residue.is_clean


@dataclass(frozen=True, slots=True)
class Binding:
    rule: Rule
    sigma: tuple[tuple[str, str], ...]
    evidence: tuple[ClauseMatch, ...]
    facts: tuple[str, ...]

    @property
    def sigma_dict(self) -> Sigma:
        return dict(self.sigma)

    @property
    def flagged(self) -> bool:
        return any(m.flagged for m in self.evidence)

    @property
    def key(self) -> tuple[str, tuple[tuple[str, str], ...]]:
        return (self.rule.id, self.sigma)


def substitute(template: str, sigma: Sigma, deployment: Deployment) -> str:
    """Replace ``{var}`` with the bound role's ARN."""

    def repl(match) -> str:
        return deployment.role_by_name(sigma[match.group(1)]).arn

    return VAR.sub(repl, template)


def _clause_matches(
    clause: ActionClause, sigma: Sigma, capabilities: Iterable[Capability], deployment: Deployment
):
    wanted = clause.action.lower()
    target = substitute(clause.resource, sigma, deployment) if clause.resource else None
    for cap in capabilities:
        if cap.action.lower() != wanted:
            continue
        if target is not None and not arn_util.matches(cap.resource, target):
            continue
        if any(not cond_util.admits(cap.conditions, key, value) for key, value in clause.condition):
            continue
        yield cap


def _fact_holds(
    fact: Fact, sigma: Sigma, deployment: Deployment, capabilities: Iterable[Capability]
) -> bool:
    def role(var_template: str) -> Role:
        name = VAR.sub(lambda m: sigma[m.group(1)], var_template)
        return deployment.role_by_name(name)

    if fact.kind == "role_trusts_service":
        return role(fact.arg("role")).trust_policy.trusts_service(fact.arg("service"))
    if fact.kind == "role_trusts_principal":
        target = role(fact.arg("role"))
        principal = role(fact.arg("principal"))
        trusted = target.trust_policy.aws_principals
        root = f"arn:aws:iam::{deployment.account_id}:root"
        return "*" in trusted or principal.arn in trusted or root in trusted
    if fact.kind == "tool_backed_by_role":
        name = role(fact.arg("role")).name
        return any(t.role == name for t in deployment.tools)
    if fact.kind == "attached_policy_matches":
        target = role(fact.arg("role"))
        wanted = fact.arg("action").lower()
        return any(
            arn_util.matches(cap.resource, policy_arn)
            for cap in capabilities
            if cap.action.lower() == wanted
            for policy_arn in target.managed_policy_arns
        )
    raise ValueError(fact.kind)


def bindings(
    rule: Rule,
    *,
    deployment: Deployment,
    capabilities: Iterable[Capability],
    principals: Iterable[str],
) -> Iterator[Binding]:
    """Every substitution under which all of the rule's clauses hold.

    ``self`` ranges over the current principals; declared variables over every role.
    One binding per satisfying σ; one evidence capability per clause (the first match,
    preferring unflagged ones).
    """
    caps = list(capabilities)
    variables = rule.all_variables
    domains = [
        sorted(principals) if v == "self" else [r.name for r in deployment.roles] for v in variables
    ]
    for combo in itertools.product(*domains) if variables else [()]:
        sigma = dict(zip(variables, combo, strict=True))
        evidence: list[ClauseMatch] = []
        ok = True
        for clause in rule.requires_actions:
            matches = list(_clause_matches(clause, sigma, caps, deployment))
            if not matches:
                ok = False
                break
            matches.sort(key=lambda c: not c.residue.is_clean)
            evidence.append(ClauseMatch(clause, matches[0]))
        if not ok:
            continue
        if not all(_fact_holds(f, sigma, deployment, caps) for f in rule.requires_facts):
            continue
        facts = tuple(_describe(f, sigma) for f in rule.requires_facts)
        yield Binding(
            rule=rule, sigma=tuple(sorted(sigma.items())), evidence=tuple(evidence), facts=facts
        )


def _describe(fact: Fact, sigma: Sigma) -> str:
    args = ", ".join(f"{k}={VAR.sub(lambda m: sigma[m.group(1)], v)}" for k, v in fact.args)
    return f"{fact.kind}({args})"
