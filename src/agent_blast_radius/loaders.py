"""Assemble a :class:`~agent_blast_radius.ir.Deployment` from ``agent.yaml``.

Two shapes are accepted:

* **Inline IR** — ``tools:`` and ``roles:`` written out by hand. The fixture's
  ``agent.yaml`` is this shape.
* **Sources + annotations** — ``sources:`` names the documents to parse (Terraform plan,
  MCP manifest, Bedrock action groups) and ``annotations:`` carries, per tool, what no
  document can: which inputs are attacker-influenced, whether output re-enters the
  model, and — unless the platform declares it — gating.

Every tool must have an annotation entry, even an empty one. A tool nobody looked at
is an error, not ``gating: none``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .errors import IRValidationError
from .ir import SCHEMA_VERSION, Deployment, Gating, Role, Tool, deployment_from_dict
from .parsers import ParsedInfra, ParsedTool, bedrock, mcp, terraform

DEPLOYMENT_FILENAMES = ("agent.yaml", "agent.yml")


def find_deployment_file(target: Path) -> Path:
    if target.is_file():
        return target
    for name in DEPLOYMENT_FILENAMES:
        candidate = target / name
        if candidate.exists():
            return candidate
    raise IRValidationError(f"no {' or '.join(DEPLOYMENT_FILENAMES)} found in {target}")


def load_deployment(target: Path) -> Deployment:
    path = find_deployment_file(target)
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise IRValidationError(f"{path}: expected a mapping at the top level")
    if "sources" in raw:
        return _from_sources(raw, base=path.parent, source=str(path))
    return deployment_from_dict(raw)


def _from_sources(raw: dict[str, Any], *, base: Path, source: str) -> Deployment:
    sources = raw["sources"] or {}
    account_id = str(raw.get("account_id", ""))
    annotations: dict[str, dict[str, Any]] = raw.get("annotations") or {}

    infra = ParsedInfra(roles=(), function_roles={})
    if "terraform_plan" in sources:
        infra = terraform.parse_file(base / sources["terraform_plan"], account_id=account_id)

    parsed: list[ParsedTool] = []
    if "mcp_tools" in sources:
        parsed += mcp.parse_file(base / sources["mcp_tools"])
    for entry in _as_list(sources.get("bedrock_action_groups")):
        parsed += bedrock.parse_file(base / entry)

    if not parsed:
        raise IRValidationError(
            f"{source}: sources produced no tools (need mcp_tools or bedrock_action_groups)"
        )

    names = [t.name for t in parsed]
    if len(names) != len(set(names)):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise IRValidationError(f"{source}: duplicate tool names across sources: {dupes}")

    unannotated = [t.name for t in parsed if t.name not in annotations]
    if unannotated:
        raise IRValidationError(
            f"{source}: every tool needs an annotations entry (even an empty one); "
            f"missing: {unannotated}"
        )
    unknown = sorted(set(annotations) - set(names))
    if unknown:
        raise IRValidationError(f"{source}: annotations for tools no source defines: {unknown}")

    role_names = {r.name for r in infra.roles}
    extra_roles = tuple(_role(r) for r in raw.get("roles", []) or [])
    role_names |= {r.name for r in extra_roles}

    tools: list[Tool] = []
    for t in parsed:
        ann = annotations[t.name] or {}
        role = ann.get("role") or _link_role(t, infra)
        if role is None:
            raise IRValidationError(
                f"{source}: tool {t.name!r}: no role. Annotate `role:` or back it with a "
                f"Lambda in the plan."
            )
        if role not in role_names:
            raise IRValidationError(f"{source}: tool {t.name!r} references unknown role {role!r}")
        gating = _gating(t, ann, source)
        tainted = frozenset(ann.get("tainted_inputs") or ())
        if t.arguments is not None and not tainted <= t.arguments:
            bad = sorted(tainted - t.arguments)
            raise IRValidationError(
                f"{source}: tool {t.name!r}: tainted_inputs {bad} are not arguments of the tool "
                f"(schema declares {sorted(t.arguments)})"
            )
        tools.append(
            Tool(
                name=t.name,
                role=role,
                gating=gating,
                tainted_inputs=tainted,
                returns_external_data=bool(ann.get("returns_external_data", False)),
                description=ann.get("description") or t.description,
            )
        )

    deployment = Deployment(
        name=raw.get("name", "unnamed"),
        tools=tuple(tools),
        roles=infra.roles + extra_roles,
        account_id=account_id,
        schema_version=raw.get("schema_version", SCHEMA_VERSION),
    )
    deployment.validate()
    return deployment


def _link_role(tool: ParsedTool, infra: ParsedInfra) -> str | None:
    if tool.function_name and tool.function_name in infra.function_roles:
        return infra.function_roles[tool.function_name]
    # lambda-tool-mcp-server convention: tool name == function name.
    return infra.function_roles.get(tool.name)


def _gating(tool: ParsedTool, ann: dict[str, Any], source: str) -> Gating:
    if "gating" in ann:
        try:
            return Gating(ann["gating"])
        except ValueError as exc:
            raise IRValidationError(
                f"{source}: tool {tool.name!r}: unknown gating {ann['gating']!r}; "
                f"expected one of {[g.value for g in Gating]}"
            ) from exc
    if tool.declared_gating is not None:
        return tool.declared_gating
    raise IRValidationError(
        f"{source}: tool {tool.name!r}: gating is neither annotated nor declared by the platform. "
        f"Set `gating:` explicitly; it is never assumed to be 'none'."
    )


def _role(raw: dict[str, Any]) -> Role:
    from .ir import _role_from_dict

    return _role_from_dict(raw)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)
