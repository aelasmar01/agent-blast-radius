"""Lookup of AWS managed policy documents from the vendored snapshot."""

from __future__ import annotations

import functools
import gzip
import json
from importlib import resources

from ..ir import PolicyDocument, policy_document_from_dict

_DATA = resources.files("agent_blast_radius") / "data"


@functools.cache
def _load() -> dict[str, dict]:
    with gzip.open(str(_DATA / "managed_policies.json.gz"), "rt") as fh:
        return json.load(fh)


def lookup(arn: str) -> PolicyDocument | None:
    """The document for an ``arn:aws:iam::aws:policy/...`` ARN, or None if not vendored."""
    entry = _load().get(arn)
    if entry is None:
        return None
    return policy_document_from_dict(entry["d"], name=entry["n"], source=arn)


def is_deprecated(arn: str) -> bool:
    entry = _load().get(arn)
    return bool(entry and entry.get("x"))


def count() -> int:
    return len(_load())
