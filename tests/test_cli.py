from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agent_blast_radius.ci import (
    EXIT_CLEAN,
    EXIT_FINDINGS,
    EXIT_FINDINGS_AND_INCOMPLETE,
    EXIT_INCOMPLETE,
    EXIT_INPUT_ERROR,
)
from agent_blast_radius.cli import main

FIXTURE = Path("fixtures/overprivileged-agent")


def test_fixture_exits_exactly_one_findings_not_incomplete(capsys, tmp_path):
    """The CI contract: the fixture fails on findings, and only on findings."""
    code = main(["scan", str(FIXTURE), "--json", str(tmp_path / "r.json")])
    assert code == EXIT_FINDINGS
    out, err = capsys.readouterr()
    assert "ACCOUNT TAKEOVER" in out
    assert "passrole-lambda-createfunction" in out
    assert "unreachable  rotate_credentials" in out
    assert "FAIL:" in err and "INCOMPLETE" not in err
    report = json.loads((tmp_path / "r.json").read_text())
    assert report["schema_version"] == "1.0.0"
    assert report["principals"]["incident-response-role"] == 1
    assert report["unsupported"] == []


def test_sources_shape_gives_the_same_verdict(capsys):
    assert main(["scan", str(FIXTURE / "agent.from-sources.yaml"), "-q"]) == EXIT_FINDINGS


def _variant(tmp_path, mutate):
    raw = yaml.safe_load((FIXTURE / "agent.yaml").read_text())
    mutate(raw)
    path = tmp_path / "agent.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path


def test_notaction_makes_it_exit_three(tmp_path, capsys):
    def inject(raw):
        for r in raw["roles"]:
            if r["name"] == "internal-api-role":
                r["identity_policies"][0]["statements"].append(
                    {"Sid": "Sneaky", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}
                )

    assert main(["scan", str(_variant(tmp_path, inject)), "-q"]) == EXIT_FINDINGS_AND_INCOMPLETE
    err = capsys.readouterr().err
    assert "NotAction at internal-api-role/invoke-internal#Sneaky" in err


def test_unsupported_only_exits_two_not_one(tmp_path):
    def defang(raw):
        for r in raw["roles"]:
            if r["name"] == "incident-response-role":
                r["trust_policy"] = {"service_principals": ["ecs-tasks.amazonaws.com"]}
            if r["name"] == "internal-api-role":
                r["identity_policies"][0]["statements"].append(
                    {"Sid": "Sneaky", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}
                )
        raw["fail_if"] = {"escalation_chains_found": True}

    assert main(["scan", str(_variant(tmp_path, defang)), "-q"]) == EXIT_INCOMPLETE


def test_clean_deployment_exits_zero(tmp_path):
    def defang(raw):
        for r in raw["roles"]:
            if r["name"] == "incident-response-role":
                r["trust_policy"] = {"service_principals": ["ecs-tasks.amazonaws.com"]}
        raw["fail_if"] = {"escalation_chains_found": True, "max_chain_depth": 3}

    assert main(["scan", str(_variant(tmp_path, defang)), "-q"]) == EXIT_CLEAN


def test_gates_are_independent(tmp_path):
    # Turn off the unsupported gate: NotAction still gets reported, but no longer fails.
    def inject(raw):
        for r in raw["roles"]:
            if r["name"] == "internal-api-role":
                r["identity_policies"][0]["statements"].append(
                    {"Sid": "Sneaky", "Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}
                )
        raw["fail_if"] = {"escalation_chains_found": True, "unsupported_statements": False}

    assert main(["scan", str(_variant(tmp_path, inject)), "-q"]) == EXIT_FINDINGS


def test_policy_file_overrides_agent_yaml(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_if:\n  reachable_actions_matching: ['dynamodb:*']\n")
    assert main(["scan", str(FIXTURE), "-q", "--policy", str(policy)]) == EXIT_FINDINGS
    policy.write_text("fail_if:\n  reachable_actions_matching: ['nosuch:*']\n")
    assert main(["scan", str(FIXTURE), "-q", "--policy", str(policy)]) == EXIT_CLEAN


def test_scan_on_missing_deployment_errors(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == EXIT_INPUT_ERROR
    assert "no agent.yaml" in capsys.readouterr().err


def test_no_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit):
        main([])
