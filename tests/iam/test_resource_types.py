"""Action-to-resource-type compatibility (divergence D7).

Found by the first differential run: the resolver took the cross product of a statement's
Actions and Resources and matched ARNs textually, reporting pairs AWS denies. These pin
both the pruning and — more importantly — the three-valued contract that keeps the
pruning from ever inventing an under-report.
"""

from __future__ import annotations

import pytest

from agent_blast_radius.iam.resolver import resolve_role
from agent_blast_radius.iam.resource_types import arn_templates, can_apply, templates_for
from agent_blast_radius.ir import _role_from_dict


@pytest.mark.parametrize(
    ("action", "resource", "expected"),
    [
        # The observed D7 cases, straight from validate/results/2026-09-02.md.
        ("sagemaker:DescribeModel", "arn:aws:sagemaker:*:*:model/*", True),
        ("sagemaker:DescribeModel", "arn:aws:sagemaker:*:*:endpoint/*", False),
        ("sagemaker:UpdateEndpoint", "arn:aws:sagemaker:*:*:endpoint/*", True),
        ("kms:DescribeKey", "arn:aws:kms:*:*:key/*", True),
        ("kms:DescribeKey", "arn:aws:kms:*:*:alias/*", False),
        # The flagship chain must survive: PassRole applies to roles, not users.
        ("iam:PassRole", "arn:aws:iam::000000000000:role/*", True),
        ("iam:PassRole", "arn:aws:iam::000000000000:user/*", False),
        ("s3:GetObject", "arn:aws:s3:::support-tickets/*", True),
        # "*" always matches, whatever the action.
        ("iam:PassRole", "*", True),
        ("s3:ListAllMyBuckets", "*", True),
    ],
)
def test_can_apply(action, resource, expected):
    assert can_apply(action, resource) is expected


def test_resourceless_action_is_only_meaningful_on_star():
    """codestar-connections:GetIndividualAccessToken has no resource type at all."""
    assert arn_templates("codestar-connections:GetIndividualAccessToken") == ()
    assert can_apply("codestar-connections:GetIndividualAccessToken", "*") is True
    assert can_apply("codestar-connections:GetIndividualAccessToken", "arn:aws:x:::y") is False


def test_unknown_action_is_undecidable_and_therefore_kept():
    """Fail open. Pruning on absent data would manufacture an under-report."""
    assert can_apply("brandnew:Thing", "arn:aws:brandnew:::x") is None
    assert arn_templates("brandnew:Thing") is None


def test_service_without_resource_templates_is_undecidable():
    assert templates_for("definitely-not-a-service") == {}


def test_resolver_prunes_incompatible_pairs_and_records_it():
    role = _role_from_dict(
        {
            "name": "r",
            "arn": "arn:aws:iam::000000000000:role/r",
            "identity_policies": [
                {
                    "name": "p",
                    "statements": [
                        {
                            "Sid": "Cross",
                            "Effect": "Allow",
                            "Action": ["sagemaker:DescribeModel", "sagemaker:UpdateEndpoint"],
                            "Resource": [
                                "arn:aws:sagemaker:*:*:model/*",
                                "arn:aws:sagemaker:*:*:endpoint/*",
                            ],
                        }
                    ],
                }
            ],
        }
    )
    res = resolve_role(role)
    pairs = {(c.action, c.resource) for c in res.capabilities}
    assert ("sagemaker:DescribeModel", "arn:aws:sagemaker:*:*:model/*") in pairs
    assert ("sagemaker:UpdateEndpoint", "arn:aws:sagemaker:*:*:endpoint/*") in pairs
    # The two cross-product pairs AWS would deny are gone.
    assert ("sagemaker:DescribeModel", "arn:aws:sagemaker:*:*:endpoint/*") not in pairs
    assert ("sagemaker:UpdateEndpoint", "arn:aws:sagemaker:*:*:model/*") not in pairs
    assert [a.kind for a in res.assumptions] == ["resource_type_pruned"]
    assert "2 (action, resource) pair(s) dropped" in res.assumptions[0].detail


def test_pruning_never_touches_the_flagship_chain():
    import yaml

    from agent_blast_radius.ir import deployment_from_dict

    d = deployment_from_dict(yaml.safe_load(open("fixtures/overprivileged-agent/agent.yaml")))
    res = resolve_role(d.role_by_name("agent-execution-role"))
    assert res.find("iam:PassRole")[0].resource == "arn:aws:iam::000000000000:role/*"
    assert res.assumptions == ()


def test_unknown_actions_survive_pruning():
    role = _role_from_dict(
        {
            "name": "r",
            "arn": "arn:aws:iam::000000000000:role/r",
            "identity_policies": [
                {
                    "name": "p",
                    "statements": [
                        {
                            "Sid": "New",
                            "Effect": "Allow",
                            "Action": ["brandnew:Thing"],
                            "Resource": ["arn:aws:brandnew:::x"],
                        }
                    ],
                }
            ],
        }
    )
    res = resolve_role(role)
    assert "brandnew:Thing" in res.actions
