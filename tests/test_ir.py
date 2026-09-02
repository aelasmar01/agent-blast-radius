"""Tests for the IR.

The IR is the contract every parser produces and every analysis stage consumes, so the
things worth pinning here are the invariants: strictness on unknown values, refusal to
silently accept a malformed deployment, and the fields that carry the security meaning.
"""

from __future__ import annotations

import pytest
import yaml

from agent_blast_radius.errors import IRValidationError
from agent_blast_radius.ir import (
    Capability,
    ConditionResidue,
    Effect,
    Gating,
    deployment_from_dict,
)

FIXTURE = "fixtures/overprivileged-agent/agent.yaml"


@pytest.fixture
def deployment():
    with open(FIXTURE) as fh:
        return deployment_from_dict(yaml.safe_load(fh))


def test_fixture_loads_and_validates(deployment):
    assert deployment.name == "overprivileged-agent"
    assert len(deployment.tools) == 5
    assert len(deployment.roles) == 5


def test_fixture_has_a_taint_entrypoint_that_returns_external_data(deployment):
    entrypoints = [t for t in deployment.tools if t.is_taint_entrypoint]
    assert [t.name for t in entrypoints] == ["read_support_ticket"]
    assert entrypoints[0].returns_external_data


def test_fixture_has_a_clean_negative(deployment):
    """A report where everything is red proves nothing — keep the gated tool."""
    gated = [t for t in deployment.tools if not t.reachable_from_model]
    assert [t.name for t in gated] == ["rotate_credentials"]
    assert gated[0].gating is Gating.APPROVAL_REQUIRED


def test_passrole_chain_preconditions_are_present(deployment):
    """The flagship finding needs both halves: the actions and the trust policy."""
    agent_role = deployment.role_by_name("agent-execution-role")
    actions = {
        action
        for policy in agent_role.identity_policies
        for statement in policy.statements
        if statement.effect is Effect.ALLOW
        for action in statement.actions
    }
    assert {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"} <= actions

    target = deployment.role_by_name("incident-response-role")
    assert target.trust_policy.trusts_service("lambda.amazonaws.com")


def test_explicit_deny_survives_parsing(deployment):
    agent_role = deployment.role_by_name("agent-execution-role")
    denies = [
        s for p in agent_role.identity_policies for s in p.statements if s.effect is Effect.DENY
    ]
    assert [s.sid for s in denies] == ["NoDirectSecretAccess"]


def test_negated_constructs_are_flagged_not_swallowed():
    raw = {
        "name": "d",
        "roles": [
            {
                "name": "r",
                "identity_policies": [
                    {
                        "name": "p",
                        "statements": [
                            {
                                "Sid": "S1",
                                "Effect": "Allow",
                                "NotAction": ["iam:*"],
                                "Resource": ["*"],
                            }
                        ],
                    }
                ],
            }
        ],
    }
    statement = deployment_from_dict(raw).roles[0].identity_policies[0].statements[0]
    assert statement.uses_negated_construct == "NotAction"


def test_unknown_gating_is_an_error_not_a_default():
    raw = {
        "name": "d",
        "roles": [{"name": "r"}],
        "tools": [{"name": "t", "role": "r", "gating": "probably_fine"}],
    }
    with pytest.raises(IRValidationError, match="unknown gating"):
        deployment_from_dict(raw)


def test_tool_referencing_unknown_role_is_an_error():
    raw = {"name": "d", "roles": [], "tools": [{"name": "t", "role": "ghost"}]}
    with pytest.raises(IRValidationError, match="unknown role"):
        deployment_from_dict(raw)


def test_duplicate_tool_names_rejected():
    raw = {
        "name": "d",
        "roles": [{"name": "r"}],
        "tools": [{"name": "t", "role": "r"}, {"name": "t", "role": "r"}],
    }
    with pytest.raises(IRValidationError, match="duplicate tool"):
        deployment_from_dict(raw)


def test_capability_is_a_triple_and_hashable():
    scoped = Capability("s3:GetObject", "arn:aws:s3:::public-assets/*")
    unscoped = Capability("s3:GetObject", "*")
    assert scoped != unscoped
    assert len({scoped, unscoped}) == 2
    assert scoped.service == "s3"


def test_capability_rejects_bare_action():
    with pytest.raises(IRValidationError):
        Capability("GetObject", "*")


def test_condition_residue_merges():
    a = ConditionResidue(("aws:PrincipalOrgID",))
    b = ConditionResidue(("aws:SourceIp",))
    assert a.merge(b).unmodeled_keys == ("aws:PrincipalOrgID", "aws:SourceIp")
    assert ConditionResidue().is_clean
    assert not a.is_clean
