"""The capability fixpoint.

Start with the capabilities of the taint-reachable roles. Apply every rule under every
satisfying binding. Each firing either adds a principal (and its capabilities) or
declares full account control. Repeat until nothing changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..iam.resolver import Resolution
from ..ir import Capability, Deployment
from .binding import Binding, bindings
from .loader import RulePack


@dataclass(frozen=True, slots=True)
class Firing:
    binding: Binding
    depth: int
    #: Role each evidence capability came from, for the printed path.
    evidence_roles: tuple[str, ...]

    @property
    def rule_id(self) -> str:
        return self.binding.rule.id

    @property
    def grants(self) -> str:
        return (
            "all_actions"
            if self.binding.rule.grants_all
            else self.binding.sigma_dict[self.binding.rule.grants_principal.strip("{}")]
        )

    def path(self) -> list[str]:
        lines = []
        for m in self.binding.evidence:
            prov = ", ".join(str(p) for p in m.capability.provenance) or "?"
            flag = (
                "  [flagged: " + ", ".join(m.capability.residue.unmodeled_keys) + "]"
                if m.flagged
                else ""
            )
            lines.append(f"{m.capability.action} on {m.capability.resource}  <- {prov}{flag}")
        for f in self.binding.facts:
            lines.append(f"fact: {f}")
        return lines


@dataclass
class Escalation:
    #: principal -> depth (0 = taint-reachable directly)
    principals: dict[str, int] = field(default_factory=dict)
    capabilities: set[Capability] = field(default_factory=set)
    firings: list[Firing] = field(default_factory=list)
    account_admin: Firing | None = None

    @property
    def max_depth(self) -> int:
        return max(self.principals.values(), default=0)

    def chains(self) -> list[Firing]:
        return list(self.firings)


def escalate(
    deployment: Deployment,
    resolutions: dict[str, Resolution],
    initial_roles: frozenset[str],
    pack: RulePack,
) -> Escalation:
    state = Escalation()
    cap_role: dict[Capability, str] = {}
    for role in sorted(initial_roles):
        state.principals[role] = 0
        for cap in resolutions[role].capabilities:
            state.capabilities.add(cap)
            cap_role.setdefault(cap, role)

    fired: set = set()
    while True:
        progressed = False
        for rule in pack.rules:
            for b in bindings(
                rule,
                deployment=deployment,
                capabilities=state.capabilities,
                principals=state.principals,
            ):
                if b.key in fired:
                    continue
                fired.add(b.key)
                evidence_roles = tuple(cap_role.get(m.capability, "?") for m in b.evidence)
                depth = 1 + max((state.principals.get(r, 0) for r in evidence_roles), default=0)
                firing = Firing(binding=b, depth=depth, evidence_roles=evidence_roles)
                state.firings.append(firing)
                if rule.grants_all:
                    if state.account_admin is None or depth < state.account_admin.depth:
                        state.account_admin = firing
                    continue
                target = firing.grants
                if target in state.principals:
                    continue
                state.principals[target] = depth
                for cap in resolutions[target].capabilities:
                    if cap not in state.capabilities:
                        state.capabilities.add(cap)
                        cap_role.setdefault(cap, target)
                progressed = True
        if not progressed:
            break
    return state
