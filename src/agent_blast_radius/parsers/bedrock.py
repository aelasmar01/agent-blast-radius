"""Bedrock agent action group → tools.

Accepts a ``GetAgentActionGroup`` response (``{"agentActionGroup": {...}}``), a bare
action group object, or a list of either. Each ``functionSchema.functions[]`` entry is a
tool; ``requireConfirmation: ENABLED`` is the platform declaring approval gating, and
``actionGroupExecutor.lambda`` links every function in the group to one Lambda — which
is why functions inside a group share a role.

``apiSchema`` (OpenAPI) action groups are accepted but yield no argument schema; taint
annotations on them are unvalidated. First on the cut list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import IRValidationError
from ..ir import Gating
from . import ParsedTool


def _function_name(lambda_arn: str | None) -> str | None:
    if not lambda_arn:
        return None
    # arn:aws:lambda:region:account:function:NAME[:alias]
    parts = lambda_arn.split(":")
    if len(parts) >= 7 and parts[5] == "function":
        return parts[6]
    return lambda_arn.rsplit("/", 1)[-1]


def parse(raw: Any, source: str = "") -> tuple[ParsedTool, ...]:
    if isinstance(raw, dict) and "agentActionGroup" in raw:
        raw = raw["agentActionGroup"]
    groups = raw if isinstance(raw, list) else [raw]
    tools: list[ParsedTool] = []
    for group in groups:
        if isinstance(group, dict) and "agentActionGroup" in group:
            group = group["agentActionGroup"]
        if not isinstance(group, dict) or "actionGroupName" not in group:
            raise IRValidationError(
                f"{source or 'bedrock action group'}: not an action group: {group!r}"
            )
        executor = group.get("actionGroupExecutor") or {}
        function_name = _function_name(executor.get("lambda"))
        functions = (group.get("functionSchema") or {}).get("functions") or []
        if not functions and group.get("apiSchema"):
            tools.append(
                ParsedTool(
                    name=group["actionGroupName"],
                    arguments=None,
                    function_name=function_name,
                    description=group.get("description", ""),
                    source=source,
                )
            )
            continue
        for fn in functions:
            confirm = fn.get("requireConfirmation")
            declared = None
            if confirm == "ENABLED":
                declared = Gating.APPROVAL_REQUIRED
            elif confirm == "DISABLED":
                declared = Gating.NONE
            tools.append(
                ParsedTool(
                    name=fn["name"],
                    arguments=frozenset((fn.get("parameters") or {}).keys()),
                    declared_gating=declared,
                    function_name=function_name,
                    description=fn.get("description", ""),
                    source=source,
                )
            )
    return tuple(tools)


def parse_file(path: Path) -> tuple[ParsedTool, ...]:
    return parse(json.loads(path.read_text()), source=str(path))
