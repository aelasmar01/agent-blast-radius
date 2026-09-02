"""Corpus loading: managed policy ARNs from ``validate/corpus.txt`` plus fixture roles."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..iam import managed
from ..ir import Deployment, PolicyDocument, Role, TrustPolicy, deployment_from_dict


@dataclass(frozen=True, slots=True)
class CorpusEntry:
    """One subject under test: a role-shaped bundle of policy documents."""

    name: str
    group: str
    role: Role
    #: Raw JSON documents, exactly what goes into ``PolicyInputList``.
    documents: tuple[str, ...]
    #: Resource ARN -> the resource-based policy governing it. In practice the trust
    #: policies of every role in the deployment, which is what makes iam:PassRole and
    #: sts:AssumeRole decidable — the flagship finding is unsound without them.
    resource_policies: tuple[tuple[str, str], ...] = ()

    @property
    def caller_arn(self) -> str:
        """Who AWS should treat as the caller. Required alongside any resource policy."""
        return self.role.arn

    @property
    def resource_policy_map(self) -> dict[str, str]:
        return dict(self.resource_policies)

    @property
    def trust_policy_json(self) -> str | None:
        return render_trust_policy(self.role.trust_policy)


def render_trust_policy(trust: TrustPolicy) -> str | None:
    principal: dict[str, list[str]] = {}
    if trust.service_principals:
        principal["Service"] = sorted(trust.service_principals)
    if trust.aws_principals:
        principal["AWS"] = sorted(trust.aws_principals)
    if not principal:
        return None
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
        }
    )


#: IAM accepts only alphanumeric ``Sid`` values in identity policies. The IR synthesizes
#: readable ones like ``statement[0]`` for provenance, which AWS rejects outright with
#: MalformedPolicyDocument — so they are dropped on the way back out. A Sid carries no
#: evaluation semantics, and every corpus policy without explicit Sids depends on this.
VALID_SID = re.compile(r"[A-Za-z0-9]+")


def _document_json(doc: PolicyDocument) -> str:
    statements = []
    for s in doc.statements:
        raw: dict = {"Effect": s.effect.value}
        if VALID_SID.fullmatch(s.sid):
            raw = {"Sid": s.sid, **raw}
        if s.actions:
            raw["Action"] = list(s.actions)
        if s.not_actions:
            raw["NotAction"] = list(s.not_actions)
        if s.resources:
            raw["Resource"] = list(s.resources)
        if s.not_resources:
            raw["NotResource"] = list(s.not_resources)
        if s.conditions:
            cond: dict[str, dict[str, list[str]]] = {}
            for op, key, values in s.conditions:
                cond.setdefault(op, {})[key] = list(values)
            raw["Condition"] = cond
        statements.append(raw)
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def load_managed_corpus(path: Path) -> list[CorpusEntry]:
    entries: list[CorpusEntry] = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        arn, _, group = line.partition(" ")
        group = group.strip() or "untagged"
        entry = managed._load().get(arn)
        if entry is None:
            raise ValueError(f"{arn} is not in the vendored snapshot")
        role = Role(
            name=entry["n"],
            arn=f"arn:aws:iam::000000000000:role/{entry['n']}",
            managed_policy_arns=(arn,),
        )
        entries.append(
            CorpusEntry(
                name=entry["n"], group=group, role=role, documents=(json.dumps(entry["d"]),)
            )
        )
    return entries


def load_fixture_corpus(path: Path) -> list[CorpusEntry]:
    """Every role of a deployment as its own corpus entry, group ``fixture``.

    Each entry carries the trust policies of *every* role in the deployment, because a
    draw against ``iam:PassRole`` on some other role's ARN is only decidable with that
    role's trust policy in hand.
    """
    target = path / "agent.yaml" if path.is_dir() else path
    deployment: Deployment = deployment_from_dict(yaml.safe_load(target.read_text()))
    resource_policies = tuple(
        (r.arn, rendered)
        for r in deployment.roles
        if r.arn and (rendered := render_trust_policy(r.trust_policy)) is not None
    )
    out: list[CorpusEntry] = []
    for role in deployment.roles:
        docs = tuple(_document_json(d) for d in role.identity_policies)
        for arn in role.managed_policy_arns:
            entry = managed._load().get(arn)
            if entry:
                docs += (json.dumps(entry["d"]),)
        out.append(
            CorpusEntry(
                name=role.name,
                group="fixture",
                role=role,
                documents=docs,
                resource_policies=resource_policies,
            )
        )
    return out
