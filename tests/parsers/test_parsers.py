from pathlib import Path

import pytest
import yaml

from agent_blast_radius.errors import IRValidationError
from agent_blast_radius.ir import Gating, deployment_from_dict
from agent_blast_radius.loaders import load_deployment
from agent_blast_radius.parsers import bedrock, mcp, terraform

FIXTURE = Path("fixtures/overprivileged-agent")


def _statements(role):
    return [
        (p.name, s.sid, s.effect.value, tuple(s.actions), tuple(s.resources))
        for p in role.identity_policies
        for s in p.statements
    ]


def test_sources_path_matches_hand_written_ir():
    by_hand = deployment_from_dict(yaml.safe_load((FIXTURE / "agent.yaml").read_text()))
    from_sources = load_deployment(FIXTURE / "agent.from-sources.yaml")

    assert {
        (t.name, t.role, t.gating, t.tainted_inputs, t.returns_external_data) for t in by_hand.tools
    } == {
        (t.name, t.role, t.gating, t.tainted_inputs, t.returns_external_data)
        for t in from_sources.tools
    }
    assert {r.name for r in by_hand.roles} == {r.name for r in from_sources.roles}
    for role in by_hand.roles:
        other = from_sources.role_by_name(role.name)
        assert other.arn == role.arn
        assert other.trust_policy.service_principals == role.trust_policy.service_principals
        assert _statements(other) == _statements(role)


def test_terraform_parser_links_lambdas_to_roles():
    import json

    infra = terraform.parse(
        json.loads((FIXTURE / "plan.json").read_text()), account_id="000000000000"
    )
    assert infra.function_roles["deploy_helper"] == "agent-execution-role"
    assert infra.function_roles["run_maintenance_job"] == "agent-execution-role"
    assert infra.function_roles["rotate_credentials"] == "incident-response-role"
    pivot = next(r for r in infra.roles if r.name == "incident-response-role")
    assert pivot.trust_policy.trusts_service("lambda.amazonaws.com")


def test_terraform_parser_rejects_lambda_without_role_reference():
    plan = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_lambda_function.x",
                        "type": "aws_lambda_function",
                        "name": "x",
                        "values": {"function_name": "x", "role": "arn:aws:iam::1:role/hardcoded"},
                    }
                ]
            }
        },
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_lambda_function.x",
                        "type": "aws_lambda_function",
                        "name": "x",
                        "expressions": {
                            "role": {"constant_value": "arn:aws:iam::1:role/hardcoded"}
                        },
                    }
                ]
            }
        },
    }
    with pytest.raises(IRValidationError, match="aws_iam_role reference"):
        terraform.parse(plan, account_id="1")


def test_mcp_parser_extracts_argument_names():
    tools = mcp.parse_file(FIXTURE / "mcp-tools.json")
    by_name = {t.name: t for t in tools}
    assert by_name["read_support_ticket"].arguments == {"ticket_id"}
    assert by_name["call_internal_api"].arguments == {"path", "body"}
    assert by_name["read_support_ticket"].declared_gating is None


def test_bedrock_parser_declares_gating_and_shares_the_lambda():
    tools = bedrock.parse_file(FIXTURE / "bedrock-action-group.json")
    by_name = {t.name: t for t in tools}
    assert by_name["deploy_helper"].declared_gating is Gating.NONE
    assert by_name["run_maintenance_job"].declared_gating is Gating.APPROVAL_REQUIRED
    assert (
        by_name["deploy_helper"].function_name
        == by_name["run_maintenance_job"].function_name
        == "deploy_helper"
    )
    assert by_name["deploy_helper"].arguments == {"code_uri", "handler"}


def _write(tmp_path, annotations, extra=""):
    (tmp_path / "agent.yaml").write_text(
        "name: t\naccount_id: '000000000000'\n"
        f"sources:\n  terraform_plan: {FIXTURE.resolve() / 'plan.json'}\n"
        f"  mcp_tools: {FIXTURE.resolve() / 'mcp-tools.json'}\n"
        f"  bedrock_action_groups: [{FIXTURE.resolve() / 'bedrock-action-group.json'}]\n"
        f"annotations:\n{annotations}{extra}"
    )
    return tmp_path


FULL = """  read_support_ticket:
    {gating: none, tainted_inputs: [ticket_id], returns_external_data: true}
  query_customer_record: {gating: none}
  call_internal_api: {gating: none}
  deploy_helper: {}
  run_maintenance_job: {}
  rotate_credentials: {gating: approval_required}
"""


def test_missing_annotation_is_an_error_listing_the_tool(tmp_path):
    with pytest.raises(IRValidationError, match=r"missing: \['rotate_credentials'\]"):
        load_deployment(
            _write(
                tmp_path, FULL.replace("  rotate_credentials: {gating: approval_required}\n", "")
            )
        )


def test_gating_is_never_assumed(tmp_path):
    with pytest.raises(IRValidationError, match="never assumed"):
        load_deployment(
            _write(
                tmp_path,
                FULL.replace("query_customer_record: {gating: none}", "query_customer_record: {}"),
            )
        )


def test_tainted_input_must_be_a_declared_argument(tmp_path):
    bad = FULL.replace("tainted_inputs: [ticket_id]", "tainted_inputs: [ticket_body]")
    with pytest.raises(IRValidationError, match="not arguments of the tool"):
        load_deployment(_write(tmp_path, bad))


def test_annotation_for_undefined_tool_is_an_error(tmp_path):
    with pytest.raises(IRValidationError, match="no source defines"):
        load_deployment(_write(tmp_path, FULL + "  ghost_tool: {gating: none}\n"))


def test_platform_declared_gating_can_be_overridden(tmp_path):
    dep = load_deployment(
        _write(
            tmp_path, FULL.replace("run_maintenance_job: {}", "run_maintenance_job: {gating: none}")
        )
    )
    assert next(t for t in dep.tools if t.name == "run_maintenance_job").gating is Gating.NONE
