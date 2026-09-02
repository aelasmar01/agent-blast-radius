"""Simulator interface and the boto3-backed implementation with throttling."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from .draws import Draw

#: One draw's AWS verdict: ``allowed`` | ``explicitDeny`` | ``implicitDeny``.
AwsDecision = str

ACTIONS_PER_CALL = 20


@dataclass(frozen=True, slots=True)
class Request:
    documents: tuple[str, ...]
    actions: tuple[str, ...]
    resource: str | None
    context: tuple[tuple[str, str], ...]
    resource_policy: str | None = None
    #: Required by the API whenever ``resource_policy`` is set: the trust policy's
    #: ``Principal`` needs a caller to evaluate against.
    caller_arn: str | None = None
    #: key -> IAM ContextKeyTypeEnum. Missing keys default to ``string``.
    context_types: tuple[tuple[str, str], ...] = ()


class Simulator(Protocol):
    def simulate(self, request: Request) -> dict[str, AwsDecision]: ...


def batch(
    documents: tuple[str, ...],
    draws: Iterable[Draw],
    resource_policies: Mapping[str, str] | None = None,
    caller_arn: str | None = None,
) -> list[Request]:
    """Group draws by (resource, context) and chunk their actions — one call per chunk.

    ``resource_policies`` maps a concrete resource ARN to the resource-based policy that
    governs it — in practice a role's trust policy, which is what makes ``iam:PassRole``
    and ``sts:AssumeRole`` decidable. The API allows one resource policy per call, and
    requests are already grouped by resource, so the mapping resolves cleanly.
    """
    resource_policies = resource_policies or {}
    groups: dict[tuple, list[str]] = {}
    for d in draws:
        groups.setdefault((d.resource, d.context, d.context_types), []).append(d.action)
    requests: list[Request] = []
    for (resource, context, context_types), actions in groups.items():
        policy = resource_policies.get(resource) if resource else None
        for i in range(0, len(actions), ACTIONS_PER_CALL):
            requests.append(
                Request(
                    documents=documents,
                    actions=tuple(actions[i : i + ACTIONS_PER_CALL]),
                    resource=resource,
                    context=context,
                    resource_policy=policy,
                    caller_arn=caller_arn if policy else None,
                    context_types=context_types,
                )
            )
    return requests


class FakeSimulator:
    """Deterministic stand-in for tests: ``decide(action, resource, context) -> decision``."""

    def __init__(self, decide: Callable[[str, str | None, dict[str, str]], AwsDecision]) -> None:
        self._decide = decide
        self.calls = 0

    def simulate(self, request: Request) -> dict[str, AwsDecision]:
        self.calls += 1
        ctx = dict(request.context)
        return {a: self._decide(a, request.resource, ctx) for a in request.actions}


class BotoSimulator:
    """``iam:SimulateCustomPolicy`` behind a token bucket.

    botocore's adaptive retry mode handles ``Throttling`` with backoff; the bucket keeps
    us well under the limit in the first place. ~5 calls/s, ~300 calls for the corpus,
    so a full run is on the order of a minute plus latency.
    """

    def __init__(self, session=None, *, calls_per_second: float = 5.0) -> None:
        from botocore.config import Config

        if session is None:
            import boto3  # only needed for a real run; tests inject a session

            session = boto3.Session()
        self._client = session.client(
            "iam", config=Config(retries={"mode": "adaptive", "max_attempts": 10})
        )
        self._interval = 1.0 / calls_per_second
        self._last = 0.0
        self.calls = 0

    def _throttle(self) -> None:
        now = time.monotonic()
        wait = self._last + self._interval - now
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def simulate(self, request: Request) -> dict[str, AwsDecision]:
        kwargs: dict = {
            "PolicyInputList": list(request.documents),
            "ActionNames": list(request.actions),
        }
        if request.resource is not None:
            kwargs["ResourceArns"] = [request.resource]
        if request.context:
            types = dict(request.context_types)
            kwargs["ContextEntries"] = [
                {
                    "ContextKeyName": key,
                    "ContextKeyValues": [value],
                    # Typed from the condition operator that produced the key. Inferring
                    # from the value would call a tag whose value is "true" a boolean.
                    "ContextKeyType": types.get(key, "string"),
                }
                for key, value in request.context
            ]
        if request.resource_policy is not None:
            kwargs["ResourcePolicy"] = request.resource_policy
            if request.caller_arn is None:
                raise ValueError(
                    "SimulateCustomPolicy requires CallerArn whenever ResourcePolicy is set: "
                    "the resource policy's Principal has nothing to evaluate against without it."
                )
            kwargs["CallerArn"] = request.caller_arn
        out: dict[str, AwsDecision] = {}
        self._throttle()
        self.calls += 1
        paginator = self._client.get_paginator("simulate_custom_policy")
        for page in paginator.paginate(**kwargs):
            for result in page["EvaluationResults"]:
                out[result["EvalActionName"]] = result["EvalDecision"]
        return out
