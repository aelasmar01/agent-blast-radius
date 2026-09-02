"""The intermediate representation.

Every input format — MCP server manifest, Bedrock action group, Terraform plan JSON —
is parsed into these types, and every downstream stage consumes only these. Frozen
dataclasses throughout: the analyzer is pure functions over immutable values, so
capability sets can live in ``frozenset``s and the reachability fixpoint can compare
states by equality.

Design notes that matter (project plan §6):

* The unit of analysis is a *triple*, not an action string. ``s3:GetObject`` on
  ``arn:aws:s3:::public-assets/*`` is a different capability from unconstrained
  ``s3:GetObject``. Flattening that reports every deployment as catastrophic.
* ``gating`` is a first-class field. Without it, every tool is reachable by default and
  taint propagation says nothing.
* ``returns_external_data`` models second-order taint — a tool whose output re-enters
  the model's context — as one flag, not a dataflow analysis.
* Single account. Cross-account reach lives in the resource-policy gap (README).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .errors import IRValidationError

#: Bumped whenever the IR or the emitted JSON report changes shape.
SCHEMA_VERSION = "0.1.0"


class Effect(StrEnum):
    ALLOW = "Allow"
    DENY = "Deny"


class Gating(StrEnum):
    """What stands between the model deciding to call a tool and the call happening."""

    #: The model calls it unilaterally.
    NONE = "none"
    #: A human approves each invocation.
    APPROVAL_REQUIRED = "approval_required"
    #: Invoked by deterministic code, not by model choice.
    DETERMINISTIC = "deterministic"


@dataclass(frozen=True, slots=True)
class ConditionResidue:
    """What the resolver could not model about a statement's ``Condition`` block.

    An empty residue means the condition was fully understood. A non-empty one means the
    capability is reported as *unconstrained but flagged* — the conservative direction,
    and one that can be defended out loud.
    """

    unmodeled_keys: tuple[str, ...] = ()

    @property
    def is_clean(self) -> bool:
        return not self.unmodeled_keys

    def merge(self, other: ConditionResidue) -> ConditionResidue:
        return ConditionResidue(tuple(sorted(set(self.unmodeled_keys) | set(other.unmodeled_keys))))


@dataclass(frozen=True, slots=True)
class Condition:
    """One modeled condition clause: ``operator`` applied to ``key`` with ``values``.

    Only clauses whose operator the resolver understands become ``Condition``s; the rest
    land in :class:`ConditionResidue`.
    """

    operator: str
    key: str
    values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Provenance:
    """Which statement granted a capability. What makes a finding credible."""

    role: str
    policy: str
    sid: str

    def __str__(self) -> str:
        return f"{self.role}/{self.policy}#{self.sid}"


@dataclass(frozen=True, slots=True)
class Capability:
    """The unit of analysis: one action, on one resource pattern, under some conditions.

    ``provenance`` is excluded from equality and hashing: two statements granting the
    same capability yield one set member, and the resolver merges their provenance.
    """

    action: str
    resource: str
    conditions: tuple[Condition, ...] = ()
    residue: ConditionResidue = ConditionResidue()
    provenance: tuple[Provenance, ...] = field(default=(), compare=False)

    def __post_init__(self) -> None:
        if ":" not in self.action:
            raise IRValidationError(f"action {self.action!r} is not of the form 'service:Action'")

    @property
    def service(self) -> str:
        return self.action.split(":", 1)[0]

    @property
    def is_unconditional(self) -> bool:
        return not self.conditions and self.residue.is_clean


@dataclass(frozen=True, slots=True)
class Unsupported:
    """Something the resolver refused to approximate, recorded instead of guessed.

    A non-empty ``unsupported`` list means the analysis is incomplete, and CI fails
    closed on it by default. ``kind`` is one of ``NotAction``, ``NotResource``,
    ``unresolved_managed_policy``, ``unknown_action``.
    """

    kind: str
    role: str
    policy: str
    sid: str
    detail: str = ""

    def __str__(self) -> str:
        where = f"{self.role}/{self.policy}#{self.sid}"
        return f"{self.kind} at {where}" + (f": {self.detail}" if self.detail else "")


@dataclass(frozen=True, slots=True)
class Statement:
    """One statement of a policy document, normalized.

    ``not_actions`` and ``not_resources`` are carried rather than expanded so that the
    resolver can raise :class:`~agent_blast_radius.errors.UnsupportedPolicyConstruct`
    with a real statement ID instead of silently producing a wrong answer.
    """

    sid: str
    effect: Effect
    actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    conditions: tuple[tuple[str, str, tuple[str, ...]], ...] = ()
    not_actions: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()

    @property
    def uses_negated_construct(self) -> str | None:
        if self.not_actions:
            return "NotAction"
        if self.not_resources:
            return "NotResource"
        return None


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """An identity policy attached to a role."""

    name: str
    statements: tuple[Statement, ...]
    #: Where this came from, for provenance in the report.
    source: str = ""


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    """Who may assume a role.

    Required, not optional: ``iam:PassRole`` + ``lambda:CreateFunction`` is only a real
    finding if the target role's trust policy admits ``lambda.amazonaws.com``. Without
    this, the flagship finding is unsound.
    """

    service_principals: frozenset[str] = frozenset()
    aws_principals: frozenset[str] = frozenset()
    source: str = ""

    def trusts_service(self, service: str) -> bool:
        return service in self.service_principals


@dataclass(frozen=True, slots=True)
class Role:
    """An IAM role a tool executes under."""

    name: str
    arn: str
    identity_policies: tuple[PolicyDocument, ...] = ()
    #: Attached AWS/customer managed policies, resolved from the vendored dataset.
    managed_policy_arns: tuple[str, ...] = ()
    trust_policy: TrustPolicy = field(default_factory=TrustPolicy)


@dataclass(frozen=True, slots=True)
class Tool:
    """A capability exposed to the model — one MCP tool or one Bedrock action group."""

    name: str
    role: str
    gating: Gating = Gating.NONE
    #: Named inputs an attacker can influence. Explicit annotation; never inferred.
    tainted_inputs: frozenset[str] = frozenset()
    #: Second-order taint: this tool's output re-enters the model's context.
    returns_external_data: bool = False
    description: str = ""

    @property
    def is_taint_entrypoint(self) -> bool:
        return bool(self.tainted_inputs)

    @property
    def reachable_from_model(self) -> bool:
        """Whether an attacker steering the model can cause this tool to be invoked."""
        return self.gating is Gating.NONE


@dataclass(frozen=True, slots=True)
class Deployment:
    """One agentic system: its tools, the roles behind them, and the taint marks."""

    name: str
    tools: tuple[Tool, ...] = ()
    roles: tuple[Role, ...] = ()
    account_id: str = ""
    schema_version: str = SCHEMA_VERSION

    def role_by_name(self, name: str) -> Role:
        for role in self.roles:
            if role.name == name:
                return role
        raise IRValidationError(f"tool references unknown role {name!r}")

    def validate(self) -> None:
        """Fail on internal inconsistency before any analysis runs."""
        names = [t.name for t in self.tools]
        if len(names) != len(set(names)):
            raise IRValidationError("duplicate tool names in deployment")
        for tool in self.tools:
            self.role_by_name(tool.role)


def deployment_from_dict(raw: dict[str, Any]) -> Deployment:
    """Build a :class:`Deployment` from parsed YAML/JSON.

    Deliberately strict: an unrecognized ``gating`` value is an error, not a default.
    """
    roles = tuple(_role_from_dict(r) for r in raw.get("roles", []))
    tools = tuple(_tool_from_dict(t) for t in raw.get("tools", []))
    deployment = Deployment(
        name=raw.get("name", "unnamed"),
        tools=tools,
        roles=roles,
        account_id=str(raw.get("account_id", "")),
        schema_version=raw.get("schema_version", SCHEMA_VERSION),
    )
    deployment.validate()
    return deployment


def _tool_from_dict(raw: dict[str, Any]) -> Tool:
    try:
        gating = Gating(raw.get("gating", "none"))
    except ValueError as exc:
        raise IRValidationError(
            f"tool {raw.get('name')!r}: unknown gating {raw.get('gating')!r}; "
            f"expected one of {[g.value for g in Gating]}"
        ) from exc
    return Tool(
        name=raw["name"],
        role=raw["role"],
        gating=gating,
        tainted_inputs=frozenset(raw.get("tainted_inputs", ())),
        returns_external_data=bool(raw.get("returns_external_data", False)),
        description=raw.get("description", ""),
    )


def _role_from_dict(raw: dict[str, Any]) -> Role:
    trust = raw.get("trust_policy", {}) or {}
    return Role(
        name=raw["name"],
        arn=raw.get("arn", ""),
        identity_policies=tuple(
            PolicyDocument(
                name=p.get("name", "inline"),
                statements=tuple(statement_from_dict(s, i) for i, s in enumerate(p["statements"])),
                source=p.get("source", ""),
            )
            for p in raw.get("identity_policies", [])
        ),
        managed_policy_arns=_as_tuple(raw.get("managed_policy_arns")),
        trust_policy=TrustPolicy(
            service_principals=frozenset(trust.get("service_principals", ())),
            aws_principals=frozenset(trust.get("aws_principals", ())),
            source=trust.get("source", ""),
        ),
    )


def statement_from_dict(raw: dict[str, Any], index: int = 0) -> Statement:
    """Normalize one raw policy statement (AWS JSON casing or lowercase YAML)."""
    conditions: list[tuple[str, str, tuple[str, ...]]] = []
    for operator, clauses in (raw.get("Condition") or raw.get("condition") or {}).items():
        for key, values in clauses.items():
            conditions.append((operator, key, _as_tuple(values)))
    return Statement(
        sid=raw.get("Sid") or raw.get("sid") or f"statement[{index}]",
        effect=Effect(raw.get("Effect", raw.get("effect", "Allow"))),
        actions=_as_tuple(raw.get("Action", raw.get("action"))),
        resources=_as_tuple(raw.get("Resource", raw.get("resource"))),
        conditions=tuple(conditions),
        not_actions=_as_tuple(raw.get("NotAction", raw.get("not_action"))),
        not_resources=_as_tuple(raw.get("NotResource", raw.get("not_resource"))),
    )


def policy_document_from_dict(raw: dict[str, Any], name: str, source: str = "") -> PolicyDocument:
    """Build a :class:`PolicyDocument` from an AWS policy JSON object."""
    statements = raw.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return PolicyDocument(
        name=name,
        statements=tuple(statement_from_dict(s, i) for i, s in enumerate(statements)),
        source=source,
    )


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str | bool | int | float):
        return (str(value).lower() if isinstance(value, bool) else str(value),)
    return tuple(str(v).lower() if isinstance(v, bool) else str(v) for v in value)
