"""Request construction for iam:SimulateCustomPolicy.

This is the only code in the project that meets real AWS first, and a mistake here does
not look like a bug — it looks like a resolver divergence. Every field is pinned.
"""

from __future__ import annotations

import pytest

from agent_blast_radius.validate.draws import Draw
from agent_blast_radius.validate.simulate import (
    ACTIONS_PER_CALL,
    BotoSimulator,
    Request,
    batch,
)

DOC = '{"Version":"2012-10-17","Statement":[]}'
TRUST = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":{"Service":["lambda.amazonaws.com"]},"Action":"sts:AssumeRole"}]}'
)
ROLE = "arn:aws:iam::000000000000:role/target"
CALLER = "arn:aws:iam::000000000000:role/caller"


class _Paginator:
    def __init__(self, client):
        self._client = client

    def paginate(self, **kwargs):
        self._client.calls.append(kwargs)
        # Two pages, to prove pagination is consumed rather than truncated.
        actions = list(kwargs["ActionNames"])
        half = max(1, len(actions) // 2)
        for chunk in (actions[:half], actions[half:]):
            if chunk:
                yield {
                    "EvaluationResults": [
                        {"EvalActionName": a, "EvalDecision": self._client.decide(a)} for a in chunk
                    ]
                }


class _Client:
    def __init__(self, decide=lambda a: "allowed"):
        self.calls: list[dict] = []
        self.decide = decide

    def get_paginator(self, name):
        assert name == "simulate_custom_policy"
        return _Paginator(self)


class _Session:
    def __init__(self, client):
        self._client = client
        self.config = None

    def client(self, service, config=None):
        assert service == "iam"
        self.config = config
        return self._client


def _simulator(decide=lambda a: "allowed"):
    client = _Client(decide)
    session = _Session(client)
    return BotoSimulator(session, calls_per_second=1000.0), client, session


def test_minimal_request_sends_only_required_fields():
    sim, client, _ = _simulator()
    sim.simulate(Request((DOC,), ("s3:GetObject",), None, ()))
    (kwargs,) = client.calls
    assert kwargs == {"PolicyInputList": [DOC], "ActionNames": ["s3:GetObject"]}


def test_resource_arns_included_only_when_present():
    sim, client, _ = _simulator()
    sim.simulate(Request((DOC,), ("s3:GetObject",), "arn:aws:s3:::b/k", ()))
    assert client.calls[0]["ResourceArns"] == ["arn:aws:s3:::b/k"]


def test_context_key_type_comes_from_the_operator_not_the_value():
    """A tag whose value is the string "true" is a string, not a boolean."""
    sim, client, _ = _simulator()
    sim.simulate(
        Request(
            (DOC,),
            ("s3:GetObject",),
            None,
            (("aws:ResourceTag/enabled", "true"), ("aws:SecureTransport", "true")),
            context_types=(
                ("aws:ResourceTag/enabled", "string"),
                ("aws:SecureTransport", "boolean"),
            ),
        )
    )
    entries = {e["ContextKeyName"]: e for e in client.calls[0]["ContextEntries"]}
    assert entries["aws:ResourceTag/enabled"]["ContextKeyType"] == "string"
    assert entries["aws:SecureTransport"]["ContextKeyType"] == "boolean"
    assert entries["aws:SecureTransport"]["ContextKeyValues"] == ["true"]


def test_untyped_context_key_defaults_to_string():
    sim, client, _ = _simulator()
    sim.simulate(Request((DOC,), ("s3:GetObject",), None, (("k", "v"),)))
    assert client.calls[0]["ContextEntries"][0]["ContextKeyType"] == "string"


def test_resource_policy_is_sent_with_caller_arn():
    """CallerArn is required by the API whenever ResourcePolicy is set."""
    sim, client, _ = _simulator()
    sim.simulate(
        Request((DOC,), ("iam:PassRole",), ROLE, (), resource_policy=TRUST, caller_arn=CALLER)
    )
    kwargs = client.calls[0]
    assert kwargs["ResourcePolicy"] == TRUST
    assert kwargs["CallerArn"] == CALLER


def test_resource_policy_without_caller_arn_raises_rather_than_calling_aws():
    sim, client, _ = _simulator()
    with pytest.raises(ValueError, match="CallerArn"):
        sim.simulate(Request((DOC,), ("iam:PassRole",), ROLE, (), resource_policy=TRUST))
    assert client.calls == []


def test_pagination_is_fully_consumed():
    sim, _, _ = _simulator()
    actions = tuple(f"s3:Act{i}" for i in range(8))
    out = sim.simulate(Request((DOC,), actions, None, ()))
    assert set(out) == set(actions)


def test_verdicts_are_returned_per_action():
    sim, _, _ = _simulator(lambda a: "explicitDeny" if a.endswith("1") else "allowed")
    out = sim.simulate(Request((DOC,), ("s3:Act1", "s3:Act2"), None, ()))
    assert out == {"s3:Act1": "explicitDeny", "s3:Act2": "allowed"}


def test_adaptive_retries_are_configured():
    _, _, session = _simulator()
    assert session.config.retries["mode"] == "adaptive"


def test_call_count_is_tracked():
    sim, _, _ = _simulator()
    for _ in range(3):
        sim.simulate(Request((DOC,), ("s3:GetObject",), None, ()))
    assert sim.calls == 3


# --- batching ------------------------------------------------------------------------


def _draw(action, resource=None, context=(), types=()):
    return Draw(action, resource, context, "uniform", "deny", context_types=types)


def test_batch_splits_on_the_action_limit():
    draws = [_draw(f"s3:Act{i}") for i in range(ACTIONS_PER_CALL * 2 + 1)]
    reqs = batch((DOC,), draws)
    assert len(reqs) == 3
    assert all(len(r.actions) <= ACTIONS_PER_CALL for r in reqs)


def test_batch_separates_differing_contexts_and_types():
    draws = [
        _draw("s3:GetObject", context=(("k", "v"),), types=(("k", "string"),)),
        _draw("s3:GetObject", context=(("k", "w"),), types=(("k", "string"),)),
        _draw("s3:GetObject", context=(("k", "v"),), types=(("k", "boolean"),)),
    ]
    assert len(batch((DOC,), draws)) == 3


def test_batch_attaches_the_matching_resource_policy_and_caller():
    draws = [_draw("iam:PassRole", ROLE), _draw("s3:GetObject", "arn:aws:s3:::b/k")]
    reqs = {r.resource: r for r in batch((DOC,), draws, {ROLE: TRUST}, CALLER)}
    assert reqs[ROLE].resource_policy == TRUST and reqs[ROLE].caller_arn == CALLER
    # No policy governs the bucket ARN, so no caller is sent either.
    assert reqs["arn:aws:s3:::b/k"].resource_policy is None
    assert reqs["arn:aws:s3:::b/k"].caller_arn is None


def test_batch_sends_no_caller_arn_when_no_policy_matches():
    reqs = batch((DOC,), [_draw("iam:PassRole", ROLE)], {}, CALLER)
    assert reqs[0].caller_arn is None
