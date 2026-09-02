"""IAM action expansion against the vendored Service Authorization Reference snapshot.

The snapshot (``data/actions.json.gz``) is built by ``scripts/build_action_dataset.py``
from a pinned commit of ``iann0036/iam-dataset``. It is the source of truth for action
names because botocore's API operation lists are not: ``iam:PassRole`` and
``s3:ListBucket`` are IAM actions with no API operation behind them.
"""

from __future__ import annotations

import fnmatch
import functools
import gzip
import json
import re
from importlib import resources

_DATA = resources.files("agent_blast_radius") / "data"


@functools.cache
def _load() -> dict[str, dict[str, dict]]:
    with gzip.open(str(_DATA / "actions.json.gz"), "rt") as fh:
        return json.load(fh)


@functools.cache
def dataset_version() -> str:
    """The pinned upstream commit, for the report header."""
    for line in (_DATA / "VERSION").read_text().splitlines():
        if line.startswith("commit:"):
            return line.split(":", 1)[1].strip()
    return "unknown"


@functools.cache
def _index() -> dict[str, dict[str, str]]:
    """{service_lower: {action_lower: CanonicalAction}}"""
    return {
        service.lower(): {name.lower(): name for name in actions}
        for service, actions in _load().items()
    }


def is_known(action: str) -> bool:
    service, _, name = action.partition(":")
    return name.lower() in _index().get(service.lower(), {})


def canonical(action: str) -> str:
    """Return the dataset's casing for a known action, or the input unchanged."""
    service, _, name = action.partition(":")
    hit = _index().get(service.lower(), {}).get(name.lower())
    return f"{service.lower()}:{hit}" if hit else action


def has_wildcard(pattern: str) -> bool:
    return "*" in pattern or "?" in pattern


def expand(pattern: str) -> frozenset[str]:
    """Expand one ``Action`` element value to canonical ``service:Action`` names.

    Matching is case-insensitive with ``*`` and ``?`` wildcards, as IAM does it.
    A literal action the snapshot doesn't know is returned as-is rather than dropped,
    so a new service under-represented in the snapshot over-reports instead of
    disappearing; callers use :func:`is_known` to flag it.
    """
    if pattern == "*":
        return frozenset(f"{svc}:{name}" for svc, acts in _load().items() for name in acts)
    service, sep, name = pattern.partition(":")
    if not sep:
        return frozenset()
    service_l = service.lower()
    if not has_wildcard(pattern):
        return frozenset({canonical(pattern)})
    out: set[str] = set()
    name_re = re.compile(fnmatch.translate(name.lower()))
    for svc, acts in _index().items():
        if not fnmatch.fnmatchcase(svc, service_l):
            continue
        for lower, canon in acts.items():
            if name_re.match(lower):
                out.add(f"{svc}:{canon}")
    return frozenset(out)


def access_level(action: str) -> str:
    """One of R/W/L/T/P (read, write, list, tagging, permissions management) or '?'."""
    service, _, name = action.partition(":")
    canon = _index().get(service.lower(), {}).get(name.lower())
    if canon is None:
        return "?"
    return _load()[service.lower()][canon].get("a", "?")


def condition_keys(action: str) -> frozenset[str]:
    service, _, name = action.partition(":")
    canon = _index().get(service.lower(), {}).get(name.lower())
    if canon is None:
        return frozenset()
    return frozenset(_load()[service.lower()][canon].get("c", ()))
