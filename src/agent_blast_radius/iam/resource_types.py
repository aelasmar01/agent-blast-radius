"""Action-to-resource-type compatibility.

A policy statement lists Actions and Resources; the resolver takes their cross product.
AWS does not: it additionally requires the resource to be of a type the action operates
on. ``sagemaker:DescribeModel`` operates on ``model``, so granting it alongside an
``endpoint/*`` ARN grants nothing, and reporting that pair as a capability is noise.

That noise was measured, not guessed: it accounted for roughly 30 of the 48 over-reports
in the first differential run (docs/divergences.md, D7).

**This module only ever removes capabilities, so it can only ever create under-reports —
the one direction this project refuses to fail in.** Every function therefore returns
``None`` rather than ``False`` whenever the data cannot decide, and the caller keeps the
capability. The three-valued return is the whole design.
"""

from __future__ import annotations

import functools
import gzip
import json
from importlib import resources

from . import actions as action_db
from .arn import overlaps

_DATA = resources.files("agent_blast_radius") / "data"


@functools.cache
def _templates() -> dict[str, dict[str, str]]:
    """{service: {resource_type: arn_glob}}"""
    with gzip.open(str(_DATA / "resource_types.json.gz"), "rt") as fh:
        return json.load(fh)


def templates_for(service: str) -> dict[str, str]:
    return _templates().get(service.lower(), {})


@functools.cache
def arn_templates(action: str) -> tuple[str, ...] | None:
    """ARN globs for the resource types ``action`` operates on.

    ``()`` means the action takes no resource and is only meaningful on ``*``.
    ``None`` means the snapshot cannot say — unknown action, or a service whose resource
    templates are missing.
    """
    if not action_db.is_known(action):
        return None
    service = action.split(":", 1)[0].lower()
    by_type = templates_for(service)
    if not by_type:
        return None
    type_names = action_db.resource_types(action)
    if not type_names:
        return ()
    globs = tuple(by_type[name.rstrip("*")] for name in type_names if name.rstrip("*") in by_type)
    # Named types that the service's resource table does not define: cannot decide.
    return globs if len(globs) == len(type_names) else None


def can_apply(action: str, resource_pattern: str) -> bool | None:
    """Could ``action`` ever apply to a resource this pattern matches?

    ``True`` possible, ``False`` provably not, ``None`` undecidable — keep the capability.
    """
    if resource_pattern == "*":
        return True
    globs = arn_templates(action)
    if globs is None:
        return None
    if not globs:
        # Resource-less action: AWS only honours it on "*", so any narrower pattern
        # grants nothing.
        return False
    return any(overlaps(resource_pattern, glob) for glob in globs)
