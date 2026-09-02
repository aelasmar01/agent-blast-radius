"""Input parsers. Each produces IR fragments; ``loaders`` assembles them.

Parsers read facts from documents — tool names and argument names from an MCP manifest,
roles and function→role links from a Terraform plan, ``requireConfirmation`` from a
Bedrock action group. They never infer taint. Taint and (where the platform doesn't
declare it) gating come from the ``annotations`` block in ``agent.yaml``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ir import Gating, Role


@dataclass(frozen=True, slots=True)
class ParsedTool:
    name: str
    #: Argument names, when the source declares a schema. Used to validate ``tainted_inputs``.
    arguments: frozenset[str] | None = None
    #: Gating the platform itself declares (Bedrock ``requireConfirmation``). Not inferred.
    declared_gating: Gating | None = None
    #: Lambda function name backing the tool, when the source says so.
    function_name: str | None = None
    description: str = ""
    source: str = ""


@dataclass(frozen=True, slots=True)
class ParsedInfra:
    roles: tuple[Role, ...]
    #: Lambda function name -> role name.
    function_roles: dict[str, str]
    source: str = ""
