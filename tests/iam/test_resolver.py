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


def test_notaction_is_recorded_and_the_scan_continues():
    role = _role(
        identity_policies=_policy(
            {"Sid": "Weird", "Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"},
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
