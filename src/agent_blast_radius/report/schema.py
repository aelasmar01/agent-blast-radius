"""The report model. Designed first; the terminal output is rendered from it."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from ..iam import actions as action_db
from ..iam.resolver import Resolution
from ..ir import Deployment, Gating
from ..reach import Reach
from ..rules.engine import Escalation, Firing
from ..rules.loader import RulePack

REPORT_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class ToolEntry:
    name: str
    role: str
    gating: str
    reachable: bool
    reason: str


@dataclass(frozen=True, slots=True)
class CapabilityEntry:
    action: str
    resource: str
    principal: str
    depth: int
    conditions: list[str]
    residue: list[str]
    provenance: list[str]
    access_level: str


@dataclass(frozen=True, slots=True)
class ChainEntry:
    rule: str
    title: str
    source: str
    grants: str
    depth: int
    binding: dict[str, str]
    flagged: bool
    path: list[str]


@dataclass(frozen=True, slots=True)
class AssumptionEntry:
    kind: str
    role: str
    policy: str
    sid: str
    detail: str


@dataclass(frozen=True, slots=True)
class UnsupportedEntry:
    kind: str
    role: str
    policy: str
    sid: str
    detail: str


@dataclass(frozen=True, slots=True)
class Report:
    deployment: str
    account_id: str
    tools: list[ToolEntry]
    principals: dict[str, int]
    reachable_capabilities: list[CapabilityEntry]
    escalation_chains: list[ChainEntry]
    account_admin: ChainEntry | None
    unsupported: list[UnsupportedEntry]
    assumptions: list[AssumptionEntry]
    notices: list[str]
    dataset_version: str
    rules_version: int
    schema_version: str = REPORT_SCHEMA_VERSION
    generated: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    @property
    def has_findings(self) -> bool:
        return bool(self.escalation_chains or self.account_admin)

    @property
    def is_incomplete(self) -> bool:
        return bool(self.unsupported)

    def to_dict(self) -> dict:
        return asdict(self)


def _chain(f: Firing) -> ChainEntry:
    return ChainEntry(
        rule=f.rule_id,
        title=f.binding.rule.title,
        source=f.binding.rule.source,
        grants=f.grants,
        depth=f.depth,
        binding=f.binding.sigma_dict,
        flagged=f.binding.flagged,
        path=f.path(),
    )


def build_report(
    deployment: Deployment,
    resolutions: dict[str, Resolution],
    reach: Reach,
    escalation: Escalation,
    pack: RulePack,
) -> Report:
    tools = [
        ToolEntry(
            name=t.name,
            role=t.role,
            gating=t.gating.value,
            reachable=t.name in reach.reachable,
            reason=reach.reachable.get(t.name) or reach.unreachable.get(t.name, ""),
        )
        for t in deployment.tools
    ]

    principal_of: dict = {}
    for principal in sorted(escalation.principals, key=lambda p: escalation.principals[p]):
        for cap in resolutions[principal].capabilities:
            principal_of.setdefault(cap, principal)
    capabilities = [
        CapabilityEntry(
            action=cap.action,
            resource=cap.resource,
            principal=principal_of.get(cap, "?"),
            depth=escalation.principals.get(principal_of.get(cap, ""), 0),
            conditions=[f"{c.operator}:{c.key}={'|'.join(c.values)}" for c in cap.conditions],
            residue=list(cap.residue.unmodeled_keys),
            provenance=[str(p) for p in cap.provenance],
            access_level=action_db.access_level(cap.action),
        )
        for cap in sorted(escalation.capabilities, key=lambda c: (c.action, c.resource))
    ]

    unsupported = [
        UnsupportedEntry(u.kind, u.role, u.policy, u.sid, u.detail)
        for role in sorted(resolutions)
        for u in resolutions[role].unsupported
    ]
    assumptions = [
        AssumptionEntry(a.kind, a.role, a.policy, a.sid, a.detail)
        for role in sorted(resolutions)
        for a in resolutions[role].assumptions
    ]

    notices: list[str] = []
    if len(deployment.roles) == 1 and all(t.gating is Gating.NONE for t in deployment.tools):
        notices.append(
            "One role and no gated tools: taint propagation adds nothing here. This report is "
            "that role's effective capability set, which Cloudsplaining or PMapper would also "
            "give you. Annotate gating (approval_required / deterministic) to get a real answer."
        )
    if not any(t.is_taint_entrypoint for t in deployment.tools):
        notices.append("No tool has tainted_inputs; nothing is reachable from attacker input.")
    if unsupported:
        notices.append(
            f"{len(unsupported)} unsupported construct(s): the analysis is incomplete and may "
            "under-report. See the unsupported section."
        )
    if assumptions:
        notices.append(
            f"{len(assumptions)} modeling assumption(s) in play. The analysis is complete but "
            "rests on them; see the assumptions section."
        )

    return Report(
        deployment=deployment.name,
        account_id=deployment.account_id,
        tools=tools,
        principals=dict(sorted(escalation.principals.items(), key=lambda kv: (kv[1], kv[0]))),
        reachable_capabilities=capabilities,
        escalation_chains=[_chain(f) for f in escalation.firings],
        account_admin=_chain(escalation.account_admin) if escalation.account_admin else None,
        unsupported=unsupported,
        assumptions=assumptions,
        notices=notices,
        dataset_version=action_db.dataset_version(),
        rules_version=pack.version,
    )
