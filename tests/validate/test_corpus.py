"""Corpus construction.

``_document_json`` re-serializes parsed IR statements back into AWS policy JSON for the
``PolicyInputList``. If it drops a ``Condition`` or mangles a ``NotAction``, the harness
compares the resolver against a *different policy than the resolver saw*, and every
divergence in the matrix is fictional. So it is checked as a round-trip fixed point.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_blast_radius.ir import TrustPolicy, policy_document_from_dict
from agent_blast_radius.validate.corpus import (
    _document_json,
    load_fixture_corpus,
    load_managed_corpus,
    render_trust_policy,
)

FIXTURE = Path("fixtures/overprivileged-agent")
CORPUS = Path("validate/corpus.txt")


def _roundtrip(doc: dict) -> dict:
    parsed = policy_document_from_dict(doc, name="p")
    return json.loads(_document_json(parsed))


def _normalize(doc: dict) -> list[dict]:
    """Statements with scalars promoted to lists, so shape differences don't count."""
    statements = doc["Statement"]
    statements = [statements] if isinstance(statements, dict) else statements
    out = []
    for s in statements:
        norm = {}
        for key, value in s.items():
            if key in ("Action", "Resource", "NotAction", "NotResource"):
                norm[key] = [value] if isinstance(value, str) else list(value)
            elif key == "Condition":
                norm[key] = {
                    op: {
                        k: ([v] if isinstance(v, str) else [str(x) for x in v])
                        for k, v in cl.items()
                    }
                    for op, cl in value.items()
                }
            else:
                norm[key] = value
        out.append(norm)
    return out


@pytest.mark.parametrize(
    "doc",
    [
        {
            "Statement": [
                {"Sid": "A", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]}
            ]
        },
        {"Statement": [{"Sid": "S", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
        {"Statement": [{"Sid": "D", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}]},
        {
            "Statement": [
                {
                    "Sid": "NR",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "NotResource": ["arn:aws:s3:::x/*"],
                }
            ]
        },
        {
            "Statement": [
                {
                    "Sid": "C",
                    "Effect": "Allow",
                    "Action": ["iam:PassRole"],
                    "Resource": ["*"],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"},
                        "Bool": {"aws:SecureTransport": "true"},
                        "ForAnyValue:StringLike": {"aws:TagKeys": ["a*", "b*"]},
                    },
                }
            ]
        },
    ],
)
def test_document_json_is_a_roundtrip_fixed_point(doc):
    once = _roundtrip(doc)
    assert _normalize(once) == _normalize(doc)
    assert _normalize(_roundtrip(once)) == _normalize(once)


def test_roundtrip_preserves_every_fixture_statement():
    for entry in load_fixture_corpus(FIXTURE):
        for raw in entry.documents:
            doc = json.loads(raw)
            assert _normalize(_roundtrip(doc)) == _normalize(doc), entry.name


def test_roundtrip_preserves_every_corpus_policy():
    for entry in load_managed_corpus(CORPUS):
        for raw in entry.documents:
            doc = json.loads(raw)
            assert _normalize(_roundtrip(doc)) == _normalize(doc), entry.name


# --- trust policies / resource policies -------------------------------------------------


def test_render_trust_policy_shapes():
    assert render_trust_policy(TrustPolicy()) is None
    rendered = json.loads(
        render_trust_policy(TrustPolicy(service_principals=frozenset({"lambda.amazonaws.com"})))
    )
    assert rendered["Statement"][0]["Principal"] == {"Service": ["lambda.amazonaws.com"]}
    assert rendered["Statement"][0]["Action"] == "sts:AssumeRole"
    both = json.loads(
        render_trust_policy(
            TrustPolicy(
                service_principals=frozenset({"ec2.amazonaws.com"}),
                aws_principals=frozenset({"arn:aws:iam::1:root"}),
            )
        )
    )
    assert set(both["Statement"][0]["Principal"]) == {"Service", "AWS"}


def test_fixture_entries_carry_every_role_trust_policy():
    entries = load_fixture_corpus(FIXTURE)
    for entry in entries:
        assert entry.caller_arn == entry.role.arn
        policies = entry.resource_policy_map
        assert "arn:aws:iam::000000000000:role/incident-response-role" in policies
        assert (
            "lambda.amazonaws.com"
            in policies["arn:aws:iam::000000000000:role/incident-response-role"]
        )


def test_managed_corpus_entries_have_no_resource_policies():
    entry = load_managed_corpus(CORPUS)[0]
    assert entry.resource_policy_map == {}


def test_unknown_arn_in_corpus_is_an_error(tmp_path):
    bad = tmp_path / "corpus.txt"
    bad.write_text("arn:aws:iam::aws:policy/NoSuchPolicyXYZ  broad-wildcard\n")
    with pytest.raises(ValueError, match="not in the vendored snapshot"):
        load_managed_corpus(bad)


def test_synthesized_sids_are_dropped_because_aws_rejects_them():
    """IAM accepts only alphanumeric Sids; the IR's `statement[0]` is MalformedPolicyDocument."""
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    out = _roundtrip(doc)
    assert "Sid" not in out["Statement"][0]


def test_explicit_sids_are_preserved():
    doc = {
        "Statement": [
            {"Sid": "KeepMe123", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    assert _roundtrip(doc)["Statement"][0]["Sid"] == "KeepMe123"


def test_no_corpus_document_ever_emits_an_invalid_sid():
    import re

    for entry in load_managed_corpus(CORPUS) + load_fixture_corpus(FIXTURE):
        for raw in entry.documents:
            for statement in json.loads(raw)["Statement"]:
                sid = statement.get("Sid")
                assert sid is None or re.fullmatch(r"[A-Za-z0-9]+", sid), (entry.name, sid)
