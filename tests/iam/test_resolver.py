import yaml

from agent_blast_radius.iam import managed
from agent_blast_radius.iam.resolver import resolve_deployment, resolve_role, unsupported_by_kind
from agent_blast_radius.ir import Provenance, Role, deployment_from_dict

FIXTURE = "fixtures/overprivileged-agent/agent.yaml"


def _fixture():
    with open(FIXTURE) as fh:
        return deployment_from_dict(yaml.safe_load(fh))


def _role(**kwargs) -> Role:
    from agent_blast_radius.ir import _role_from_dict

    return _role_from_dict({"name": "r", "arn": "arn:aws:iam::000000000000:role/r", **kwargs})


def _policy(*statements):
    return [{"name": "p", "statements": list(statements)}]


def test_fixture_pivot_role_has_passrole_and_not_the_denied_secret():
    res = resolve_role(_fixture().role_by_name("agent-execution-role"))
    passrole = res.find("iam:PassRole")
    assert len(passrole) == 1
    assert passrole[0].resource == "arn:aws:iam::000000000000:role/*"
    assert passrole[0].provenance == (
        Provenance("agent-execution-role", "helper-deploy", "PassRoleToLambda"),
    )
    assert "lambda:CreateFunction" in res.actions
    assert "secretsmanager:GetSecretValue" not in res.actions  # explicit Deny wins
    assert res.unsupported == ()


def test_fixture_target_role_expands_iam_star():
    res = resolve_role(_fixture().role_by_name("incident-response-role"))
    assert "iam:PassRole" in res.actions
    assert "iam:CreateAccessKey" in res.actions
    assert "kms:Decrypt" in res.actions


def test_fixture_resolves_cleanly():
    assert unsupported_by_kind(resolve_deployment(_fixture())) == {}


def test_refused_statement_is_recorded_and_the_scan_continues():
    """A Deny + NotAction is skipped and recorded; the rest of the policy still resolves."""
    role = _role(
        identity_policies=_policy(
            {"Sid": "Weird", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"},
            {"Sid": "Fine", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        )
    )
    res = resolve_role(role)
    assert res.actions == {"s3:GetObject"}
    assert [(u.kind, u.sid) for u in res.unsupported] == [("NotAction", "Weird")]


def test_notresource_is_recorded():
    role = _role(
        identity_policies=_policy(
            {
                "Sid": "NR",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "NotResource": ["arn:aws:s3:::x/*"],
            },
        )
    )
    res = resolve_role(role)
    assert res.capabilities == frozenset()
    assert res.unsupported[0].kind == "NotResource"


def test_deny_subsumption_partial_and_conditional():
    role = _role(
        identity_policies=_policy(
            {
                "Sid": "A",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::public/*", "arn:aws:s3:::*", "arn:aws:s3:::logs/*"],
            },
            {
                "Sid": "D1",
                "Effect": "Deny",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::public/*"],
            },
            {
                "Sid": "D2",
                "Effect": "Deny",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::logs/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        )
    )
    res = resolve_role(role)
    by_resource = {c.resource: c for c in res.capabilities}
    assert "arn:aws:s3:::public/*" not in by_resource  # fully subsumed by D1 -> removed
    assert "deny-partial:r/p#D1" in by_resource["arn:aws:s3:::*"].residue.unmodeled_keys
    assert "deny-conditional:r/p#D2" in by_resource["arn:aws:s3:::logs/*"].residue.unmodeled_keys


def test_deny_with_wildcard_action_removes_expanded_allows():
    role = _role(
        identity_policies=_policy(
            {"Sid": "A", "Effect": "Allow", "Action": ["iam:*"], "Resource": "*"},
            {"Sid": "D", "Effect": "Deny", "Action": ["iam:Pass*"], "Resource": "*"},
        )
    )
    res = resolve_role(role)
    assert "iam:PassRole" not in res.actions
    assert "iam:CreateUser" in res.actions


def test_unmodeled_condition_keeps_capability_and_flags_it():
    role = _role(
        identity_policies=_policy(
            {
                "Sid": "C",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "*",
                "Condition": {"StringEqualsIfExists": {"aws:ResourceTag/team": "x"}},
            },
        )
    )
    cap = next(iter(resolve_role(role).capabilities))
    assert cap.residue.unmodeled_keys == ("StringEqualsIfExists:aws:ResourceTag/team",)
    assert not cap.is_unconditional


def test_modeled_condition_is_carried_on_the_capability():
    role = _role(
        identity_policies=_policy(
            {
                "Sid": "P",
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}},
            },
        )
    )
    cap = resolve_role(role).find("iam:PassRole")[0]
    assert cap.conditions[0].key == "iam:PassedToService"
    assert cap.residue.is_clean


def test_duplicate_grants_merge_provenance():
    role = _role(
        identity_policies=_policy(
            {"Sid": "One", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Sid": "Two", "Effect": "Allow", "Action": ["s3:Get*"], "Resource": "*"},
        )
    )
    res = resolve_role(role)
    cap = res.find("s3:GetObject")[0]
    assert [p.sid for p in cap.provenance] == ["One", "Two"]


def test_managed_policy_attachment_resolves_offline():
    role = _role(
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )
    res = resolve_role(role)
    assert {"logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"} <= res.actions
    assert res.unsupported == ()
    assert managed.count() > 1000


def test_unknown_managed_policy_is_unsupported_not_fatal():
    role = _role(managed_policy_arns=["arn:aws:iam::123456789012:policy/customer-thing"])
    res = resolve_role(role)
    assert res.unsupported[0].kind == "unresolved_managed_policy"


def test_unknown_literal_action_is_kept_and_flagged():
    role = _role(
        identity_policies=_policy(
            {"Sid": "N", "Effect": "Allow", "Action": ["brandnew:Thing"], "Resource": "*"}
        )
    )
    res = resolve_role(role)
    assert "brandnew:Thing" in res.actions
    assert res.unsupported[0].kind == "unknown_action"


# --- Allow + NotAction inversion -------------------------------------------------------
#
# Verified against live AWS authorization decisions in account 234612058514 on
# 2026-09-01, where the identity carries PowerUserAccess; see
# validate/results/2026-09-01-live-authorization-probe.md. Those observations are the
# reason these expectations are what they are.

POWER_USER = "arn:aws:iam::aws:policy/PowerUserAccess"


def _power_user():
    return resolve_role(_role(managed_policy_arns=[POWER_USER]))


def test_allow_notaction_is_inverted_not_refused():
    res = _power_user()
    assert res.unsupported == ()
    assert [a.kind for a in res.assumptions] == ["notaction_inverted"]
    assert "NotAction" in res.assumptions[0].detail


def test_inverted_grant_matches_live_aws_decisions():
    res = _power_user()
    for action in (
        "s3:ListAllMyBuckets",
        "lambda:ListFunctions",
        "dynamodb:ListTables",
        "ec2:DescribeInstances",
        "iam:ListRoles",
        "account:ListRegions",
        "organizations:DescribeOrganization",
    ):
        assert action in res.actions, action
    # Excluded by NotAction and not re-granted by the explicit allow list.
    for action in (
        "iam:SimulateCustomPolicy",
        "iam:CreateUser",
        "iam:ListUsers",
        "iam:GetAccountSummary",
    ):
        assert action not in res.actions, action


def test_inversion_covers_the_action_universe_minus_exclusions():
    from agent_blast_radius.iam import actions as action_db

    res = _power_user()
    universe = action_db.expand("*")
    excluded = (
        action_db.expand("iam:*")
        | action_db.expand("organizations:*")
        | action_db.expand("account:*")
    )
    # Everything outside the exclusions is granted; the re-granted few come back via the
    # policy's second statement.
    assert (universe - excluded) <= res.actions
    assert not (excluded - res.actions) == excluded  # some exclusions are re-granted


def test_deny_notaction_is_still_refused():
    """Inverting a Deny would shrink the denied set on a stale snapshot: a false negative."""
    role = _role(
        identity_policies=_policy(
            {"Sid": "A", "Effect": "Allow", "Action": ["s3:*"], "Resource": "*"},
            {"Sid": "D", "Effect": "Deny", "NotAction": ["s3:GetObject"], "Resource": "*"},
        )
    )
    res = resolve_role(role)
    assert [(u.kind, u.sid) for u in res.unsupported] == [("NotAction", "D")]
    assert res.assumptions == ()


def test_notresource_is_still_refused_even_with_notaction():
    """ARNs are not enumerable, so NotResource cannot be inverted the way NotAction can."""
    role = _role(
        identity_policies=_policy(
            {
                "Sid": "NR",
                "Effect": "Allow",
                "NotAction": ["iam:*"],
                "NotResource": ["arn:aws:s3:::x/*"],
            },
        )
    )
    res = resolve_role(role)
    assert [u.kind for u in res.unsupported] == ["NotAction"]
    assert res.capabilities == frozenset()


def test_inverted_statement_respects_its_resource_and_deny():
    role = _role(
        identity_policies=_policy(
            {
                "Sid": "Inv",
                "Effect": "Allow",
                "NotAction": ["iam:*"],
                "Resource": ["arn:aws:s3:::b/*"],
            },
            {"Sid": "D", "Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "*"},
        )
    )
    res = resolve_role(role)
    assert {c.resource for c in res.capabilities} == {"arn:aws:s3:::b/*"}
    assert "s3:DeleteObject" not in res.actions
    assert "s3:GetObject" in res.actions
