"""``terraform show -json`` plan → roles and Lambda function→role links.

Reads ``planned_values`` for attribute values and ``configuration`` for references,
because at plan time a role's ARN is unknown and the only way to know which role a
Lambda or an inline policy points at is the ``aws_iam_role.<name>`` reference in its
configuration expression. Role ARNs are synthesized from the deployment's account ID.

Handled resources: ``aws_iam_role`` (``assume_role_policy``, ``managed_policy_arns``),
``aws_iam_role_policy``, ``aws_iam_role_policy_attachment``, ``aws_lambda_function``.
Nested modules are walked. Anything else is ignored.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import IRValidationError
from ..ir import PolicyDocument, Role, TrustPolicy, policy_document_from_dict
from . import ParsedInfra


def _walk_values(module: dict[str, Any]):
    yield from module.get("resources", [])
    for child in module.get("child_modules", []):
        yield from _walk_values(child)


def _walk_config(module: dict[str, Any]):
    yield from module.get("resources", [])
    for call in (module.get("module_calls") or {}).values():
        yield from _walk_config(call.get("module", {}))


def _role_ref(expressions: dict[str, Any], attr: str) -> str | None:
    """The ``aws_iam_role.<name>`` a resource attribute references, if any."""
    refs = (expressions.get(attr) or {}).get("references") or []
    for ref in refs:
        parts = ref.split(".")
        if len(parts) >= 2 and parts[0] == "aws_iam_role":
            return f"aws_iam_role.{parts[1]}"
    return None


def _constant(expressions: dict[str, Any], attr: str) -> Any:
    return (expressions.get(attr) or {}).get("constant_value")


def _trust_from_json(text: str | None) -> TrustPolicy:
    if not text:
        return TrustPolicy()
    doc = json.loads(text)
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    services: set[str] = set()
    aws: set[str] = set()
    for s in statements:
        if s.get("Effect") != "Allow":
            continue
        principal = s.get("Principal") or {}
        if principal == "*":
            aws.add("*")
            continue
        for kind, target in (("Service", services), ("AWS", aws)):
            value = principal.get(kind)
            if isinstance(value, str):
                target.add(value)
            elif isinstance(value, list):
                target.update(value)
    return TrustPolicy(frozenset(services), frozenset(aws))


def parse(plan: dict[str, Any], *, account_id: str, source: str = "") -> ParsedInfra:
    values = {
        r["address"]: r for r in _walk_values(plan.get("planned_values", {}).get("root_module", {}))
    }
    config = {
        r["address"]: r for r in _walk_config(plan.get("configuration", {}).get("root_module", {}))
    }

    # Role resource address -> role name.
    role_names: dict[str, str] = {}
    inline: dict[str, list[PolicyDocument]] = {}
    attachments: dict[str, list[str]] = {}
    trusts: dict[str, TrustPolicy] = {}
    for address, res in values.items():
        if res["type"] != "aws_iam_role":
            continue
        v = res["values"]
        name = v.get("name")
        if not name:
            raise IRValidationError(
                f"{source}: {address} has no static name; name_prefix is not supported"
            )
        role_names[address] = name
        trusts[name] = _trust_from_json(v.get("assume_role_policy"))
        attachments.setdefault(name, []).extend(v.get("managed_policy_arns") or [])
        inline.setdefault(name, [])

    for address, res in values.items():
        expressions = config.get(address, {}).get("expressions", {})
        if res["type"] == "aws_iam_role_policy":
            ref = _role_ref(expressions, "role")
            role = role_names.get(ref or "")
            if role is None:
                raise IRValidationError(
                    f"{source}: {address} does not reference an aws_iam_role in this plan"
                )
            v = res["values"]
            doc = policy_document_from_dict(
                json.loads(v["policy"]), name=v.get("name") or res["name"], source=address
            )
            inline[role].append(doc)
        elif res["type"] == "aws_iam_role_policy_attachment":
            ref = _role_ref(expressions, "role")
            role = role_names.get(ref or "")
            if role is None:
                raise IRValidationError(
                    f"{source}: {address} does not reference an aws_iam_role in this plan"
                )
            policy_arn = res["values"].get("policy_arn") or _constant(expressions, "policy_arn")
            if not policy_arn:
                raise IRValidationError(f"{source}: {address} has no static policy_arn")
            attachments[role].append(policy_arn)

    function_roles: dict[str, str] = {}
    for address, res in values.items():
        if res["type"] != "aws_lambda_function":
            continue
        ref = _role_ref(config.get(address, {}).get("expressions", {}), "role")
        role = role_names.get(ref or "")
        fn = res["values"].get("function_name")
        if role is None or not fn:
            raise IRValidationError(
                f"{source}: {address} needs a static function_name and an aws_iam_role reference"
            )
        function_roles[fn] = role

    roles = tuple(
        Role(
            name=name,
            arn=f"arn:aws:iam::{account_id}:role/{name}",
            identity_policies=tuple(inline[name]),
            managed_policy_arns=tuple(attachments[name]),
            trust_policy=trusts[name],
        )
        for name in role_names.values()
    )
    return ParsedInfra(roles=roles, function_roles=function_roles, source=source)


def parse_file(path: Path, *, account_id: str) -> ParsedInfra:
    return parse(json.loads(path.read_text()), account_id=account_id, source=str(path))
