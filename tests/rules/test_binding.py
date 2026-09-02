"""Pins docs/rule-semantics.md."""

import yaml

from agent_blast_radius.iam.resolver import resolve_deployment
from agent_blast_radius.ir import deployment_from_dict
from agent_blast_radius.reach import compute_reach
from agent_blast_radius.rules.binding import bindings
from agent_blast_radius.rules.engine import escalate
from agent_blast_radius.rules.loader import load_rules

FIXTURE = "fixtures/overprivileged-agent/agent.yaml"


def _fixture(mutate=None):
    raw = yaml.safe_load(open(FIXTURE))
    if mutate:
        mutate(raw)
    return deployment_from_dict(raw)


def _run(deployment):
    res = resolve_deployment(deployment)
    reach = compute_reach(deployment)
    return escalate(deployment, res, reach.roles, load_rules()), reach


def test_rule_pack_is_cited_and_explained():
    pack = load_rules()
    assert 10 <= len(pack.rules) <= 15
    for r in pack.rules:
        assert r.source
        assert r.requires_facts or r.notes


def test_headline_finding():
    """This agent's tools look scoped. Three hops of IAM later, prompt injection is takeover."""
    esc, reach = _run(_fixture())
    assert reach.reachable.keys() == {
        "read_support_ticket",
        "query_customer_record",
        "call_internal_api",
        "deploy_helper",
    }
    assert set(reach.unreachable) == {"run_maintenance_job", "rotate_credentials"}
    assert (
        "incident-response-role" in esc.principals and esc.principals["incident-response-role"] == 1
    )
    fired = {f.rule_id for f in esc.firings}
    assert "passrole-lambda-createfunction" in fired
    assert any(
        c.action == "secretsmanager:GetSecretValue" and c.resource == "*" for c in esc.capabilities
    )
    # iam:* on the pivot target means AttachRolePolicy on self fires next: account takeover.
    assert esc.account_admin is not None and esc.account_admin.depth == 2


def test_trust_policy_is_load_bearing():
    def strip_trust(raw):
        for r in raw["roles"]:
            if r["name"] == "incident-response-role":
                r["trust_policy"] = {"service_principals": ["ecs-tasks.amazonaws.com"]}

    esc, _ = _run(_fixture(strip_trust))
    assert "incident-response-role" not in esc.principals
    assert esc.account_admin is None


def test_gating_blocks_the_direct_door():
    """rotate_credentials holds iam:* directly but is gated; the only way in is PassRole."""

    def gate_helper(raw):
        for t in raw["tools"]:
            if t["name"] == "deploy_helper":
                t["gating"] = "approval_required"

    esc, reach = _run(_fixture(gate_helper))
    assert "agent-execution-role" not in reach.roles
    assert "incident-response-role" not in esc.principals


def test_three_trusting_roles_yield_three_firings():
    def add_roles(raw):
        for i in (1, 2):
            raw["roles"].append(
                {
                    "name": f"extra-{i}",
                    "arn": f"arn:aws:iam::000000000000:role/extra-{i}",
                    "trust_policy": {"service_principals": ["lambda.amazonaws.com"]},
                    "identity_policies": [
                        {
                            "name": "p",
                            "statements": [
                                {
                                    "Sid": "S",
                                    "Effect": "Allow",
                                    "Action": ["s3:ListBucket"],
                                    "Resource": "*",
                                }
                            ],
                        }
                    ],
                }
            )

    esc, _ = _run(_fixture(add_roles))
    passrole = [f for f in esc.firings if f.rule_id == "passrole-lambda-createfunction"]
    targets = sorted(f.binding.sigma_dict["target"] for f in passrole)
    # incident-response-role, extra-1, extra-2, and the three lambda-trusting tool roles.
    assert {"incident-response-role", "extra-1", "extra-2"} <= set(targets)
    assert len(targets) == len(set(targets))  # one firing per binding, never duplicated


def test_passedtoservice_condition_blocks_the_chain():
    def constrain(raw):
        for r in raw["roles"]:
            if r["name"] == "agent-execution-role":
                r["identity_policies"][0]["statements"][0]["Condition"] = {
                    "StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}
                }

    esc, _ = _run(_fixture(constrain))
    assert not [f for f in esc.firings if f.rule_id == "passrole-lambda-createfunction"]


def test_bindings_do_not_leak_between_rules():
    deployment = _fixture()
    res = resolve_deployment(deployment)
    pack = load_rules()
    caps = set().union(*(res[r].capabilities for r in ("agent-execution-role",)))
    b = list(
        bindings(
            pack.by_id("passrole-lambda-createfunction"),
            deployment=deployment,
            capabilities=caps,
            principals={"agent-execution-role"},
        )
    )
    assert all(set(x.sigma_dict) == {"target"} for x in b)
    s = list(
        bindings(
            pack.by_id("iam-attachrolepolicy-self"),
            deployment=deployment,
            capabilities=caps,
            principals={"agent-execution-role"},
        )
    )
    assert s == []  # agent-execution-role has no iam:AttachRolePolicy


def test_flagged_evidence_marks_the_firing():
    def add_residue(raw):
        for r in raw["roles"]:
            if r["name"] == "agent-execution-role":
                r["identity_policies"][0]["statements"][1]["Condition"] = {
                    "StringEqualsIfExists": {"aws:ResourceTag/env": "prod"}
                }

    esc, _ = _run(_fixture(add_residue))
    f = next(f for f in esc.firings if f.rule_id == "passrole-lambda-createfunction")
    assert f.binding.flagged
    assert any("[flagged:" in line for line in f.path())


def test_depth_and_provenance_path():
    esc, _ = _run(_fixture())
    f = next(
        f
        for f in esc.firings
        if f.rule_id == "passrole-lambda-createfunction" and f.grants == "incident-response-role"
    )
    assert f.depth == 1
    path = "\n".join(f.path())
    assert (
        "iam:PassRole on arn:aws:iam::000000000000:role/*  "
        "<- agent-execution-role/helper-deploy#PassRoleToLambda" in path
    )
    assert (
        "fact: role_trusts_service(role=incident-response-role, service=lambda.amazonaws.com)"
        in path
    )
