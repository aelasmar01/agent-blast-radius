"""Load and validate ``rules/escalation.yaml``."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import yaml

from ..errors import IRValidationError

VAR = re.compile(r"\{([a-z_]+)\}")
FACT_KINDS = frozenset(
    {
        "role_trusts_service",
        "role_trusts_principal",
        "tool_backed_by_role",
        "attached_policy_matches",
    }
)


@dataclass(frozen=True, slots=True)
class ActionClause:
    action: str
    resource: str | None = None
    condition: tuple[tuple[str, str], ...] = ()

    @property
    def variables(self) -> frozenset[str]:
        found: set[str] = set()
        if self.resource:
            found.update(VAR.findall(self.resource))
        return frozenset(found)


@dataclass(frozen=True, slots=True)
class Fact:
    kind: str
    args: tuple[tuple[str, str], ...]

    @property
    def variables(self) -> frozenset[str]:
        return frozenset(v for _, value in self.args for v in VAR.findall(value))

    def arg(self, name: str) -> str:
        return dict(self.args)[name]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    variables: tuple[str, ...]
    requires_actions: tuple[ActionClause, ...]
    requires_facts: tuple[Fact, ...]
    grants_principal: str | None
    grants_all: bool
    source: str
    notes: str = ""

    @property
    def all_variables(self) -> tuple[str, ...]:
        """Declared variables plus ``self`` if any clause references it."""
        used: set[str] = set(self.variables)
        for c in self.requires_actions:
            used |= c.variables
        for f in self.requires_facts:
            used |= f.variables
        if self.grants_principal:
            used |= set(VAR.findall(self.grants_principal))
        ordered = list(self.variables)
        if "self" in used and "self" not in ordered:
            ordered.append("self")
        undeclared = used - set(ordered)
        if undeclared:
            raise IRValidationError(f"rule {self.id}: undeclared variables {sorted(undeclared)}")
        return tuple(ordered)


@dataclass(frozen=True, slots=True)
class RulePack:
    version: int
    rules: tuple[Rule, ...]
    source: str = ""

    def by_id(self, rule_id: str) -> Rule:
        for r in self.rules:
            if r.id == rule_id:
                return r
        raise KeyError(rule_id)


def _clause(raw) -> ActionClause:
    if isinstance(raw, str):
        return ActionClause(action=raw)
    cond = tuple(sorted((k, str(v)) for k, v in (raw.get("condition") or {}).items()))
    return ActionClause(action=raw["action"], resource=raw.get("resource"), condition=cond)


def _fact(raw: dict) -> Fact:
    if len(raw) != 1:
        raise IRValidationError(f"fact must have exactly one kind: {raw!r}")
    kind, args = next(iter(raw.items()))
    if kind not in FACT_KINDS:
        raise IRValidationError(f"unknown fact kind {kind!r}; known: {sorted(FACT_KINDS)}")
    return Fact(kind=kind, args=tuple(sorted((k, str(v)) for k, v in (args or {}).items())))


def _rule(raw: dict) -> Rule:
    for key in ("id", "requires_actions", "grants", "source"):
        if key not in raw:
            raise IRValidationError(f"rule {raw.get('id', '?')}: missing {key!r}")
    grants = raw["grants"] or {}
    principal = grants.get("effective_principal")
    grants_all = bool(grants.get("all_actions"))
    if bool(principal) == grants_all:
        raise IRValidationError(
            f"rule {raw['id']}: grants must be exactly one of effective_principal / all_actions"
        )
    if "requires_facts" not in raw:
        raise IRValidationError(
            f"rule {raw['id']}: requires_facts must be present (use [] and explain in notes)"
        )
    if not raw["requires_facts"] and not raw.get("notes"):
        raise IRValidationError(f"rule {raw['id']}: no requires_facts and no notes explaining why")
    rule = Rule(
        id=raw["id"],
        title=raw.get("title", raw["id"]),
        variables=tuple(raw.get("variables") or ()),
        requires_actions=tuple(_clause(c) for c in raw["requires_actions"]),
        requires_facts=tuple(_fact(f) for f in raw["requires_facts"]),
        grants_principal=principal,
        grants_all=grants_all,
        source=str(raw["source"]),
        notes=str(raw.get("notes", "")).strip(),
    )
    _ = rule.all_variables  # validates declared vs used
    return rule


def load_rules(path: Path | None = None) -> RulePack:
    if path is None:
        text = (
            resources.files("agent_blast_radius") / "data" / "rules" / "escalation.yaml"
        ).read_text()
        source = "bundled"
    else:
        text = path.read_text()
        source = str(path)
    raw = yaml.safe_load(text)
    rules = tuple(_rule(r) for r in raw.get("rules", []))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise IRValidationError("duplicate rule ids")
    return RulePack(version=int(raw.get("version", 1)), rules=rules, source=source)
