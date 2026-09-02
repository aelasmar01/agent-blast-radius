from agent_blast_radius.iam.conditions import admits, evaluate, restricts, split
from agent_blast_radius.ir import Condition


def test_split_partitions_modeled_from_residue():
    raw = (
        ("StringEquals", "iam:PassedToService", ("lambda.amazonaws.com",)),
        ("StringEqualsIfExists", "aws:ResourceTag/env", ("prod",)),
        ("ForAnyValue:StringLike", "aws:TagKeys", ("x*",)),
    )
    modeled, residue = split(raw)
    assert modeled == (Condition("StringEquals", "iam:PassedToService", ("lambda.amazonaws.com",)),)
    assert residue.unmodeled_keys == (
        "ForAnyValue:StringLike:aws:TagKeys",
        "StringEqualsIfExists:aws:ResourceTag/env",
    )


def test_evaluate_operators():
    conds = (
        Condition("StringEquals", "aws:SourceAccount", ("000000000000",)),
        Condition("StringLike", "aws:PrincipalArn", ("arn:aws:iam::*:role/ci-*",)),
        Condition("ArnLike", "aws:SourceArn", ("arn:aws:lambda:*:000000000000:function:*",)),
        Condition("Bool", "aws:SecureTransport", ("true",)),
    )
    ok = {
        "aws:SourceAccount": "000000000000",
        "aws:PrincipalArn": "arn:aws:iam::000000000000:role/ci-deploy",
        "aws:SourceArn": "arn:aws:lambda:us-east-1:000000000000:function:x",
        "aws:securetransport": "True",  # key case-insensitive, Bool value case-insensitive
    }
    assert evaluate(conds, ok)
    assert not evaluate(conds, {**ok, "aws:SourceAccount": "111111111111"})
    assert not evaluate(
        conds, {k: v for k, v in ok.items() if k != "aws:SourceArn"}
    )  # missing key fails


def test_restricts_and_admits():
    conds = (Condition("StringEquals", "iam:PassedToService", ("ecs-tasks.amazonaws.com",)),)
    assert restricts(conds, "iam:passedtoservice") == ("ecs-tasks.amazonaws.com",)
    assert not admits(conds, "iam:PassedToService", "lambda.amazonaws.com")
    assert admits((), "iam:PassedToService", "lambda.amazonaws.com")
