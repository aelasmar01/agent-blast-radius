"""Report model and terminal rendering.

The terminal output is rendered from the JSON model, never from the IR, so the two can
never disagree. These pin the sections a reader depends on.
"""

from __future__ import annotations

import yaml

from agent_blast_radius.analyze import analyze
from agent_blast_radius.ir import deployment_from_dict
from agent_blast_radius.report.terminal import render

FIXTURE = "fixtures/overprivileged-agent/agent.yaml"


def _deployment(mutate=None):
    raw = yaml.safe_load(open(FIXTURE))
    if mutate:
        mutate(raw)
    return deployment_from_dict(raw)


def test_report_shape():
    r = analyze(_deployment())
    assert r.schema_version == "1.0.0"
    assert r.has_findings and not r.is_incomplete
    assert r.dataset_version and r.rules_version == 1
    assert {t.name for t in r.tools if not t.reachable} == {
        "run_maintenance_job",
        "rotate_credentials",
    }
    assert "score" not in r.to_dict()


def test_capability_provenance_and_access_level():
    """Two roles grant iam:PassRole; each keeps its own provenance and resource scope."""
    r = analyze(_deployment())
    by_resource = {c.resource: c for c in r.reachable_capabilities if c.action == "iam:PassRole"}
    scoped = by_resource["arn:aws:iam::000000000000:role/*"]
    assert scoped.provenance == ["agent-execution-role/helper-deploy#PassRoleToLambda"]
    assert scoped.principal == "agent-execution-role" and scoped.depth == 0
    assert scoped.access_level == "P"
    # The same action reached one hop later, via iam:* on the pivot target.
    broad = by_resource["*"]
    assert broad.provenance == ["incident-response-role/break-glass#BreakGlass"]
    assert broad.principal == "incident-response-role" and broad.depth == 1


def test_terminal_renders_every_section():
    out = render(analyze(_deployment()).to_dict())
    for section in (
        "TOOLS",
        "PRINCIPALS REACHABLE FROM ATTACKER INPUT",
        "ACCOUNT TAKEOVER",
        "ESCALATION CHAINS",
        "REACHABLE CAPABILITIES",
        "UNSUPPORTED",
    ):
        assert section in out
    assert "Reachability is not exploitability" in out
    assert "gated: approval_required" in out


def test_terminal_renders_assumptions_when_present():
    def attach_power_user(raw):
        raw["roles"][0]["managed_policy_arns"] = ["arn:aws:iam::aws:policy/PowerUserAccess"]

    report = analyze(_deployment(attach_power_user))
    assert [a.kind for a in report.assumptions] == ["notaction_inverted"]
    out = render(report.to_dict())
    assert "ASSUMPTIONS (1)" in out
    assert "notaction_inverted" in out
    assert "modeling assumption" in out  # the notice


def test_terminal_reports_no_chains_without_inventing_one():
    def defang(raw):
        for r in raw["roles"]:
            if r["name"] == "incident-response-role":
                r["trust_policy"] = {"service_principals": ["ecs-tasks.amazonaws.com"]}

    out = render(analyze(_deployment(defang)).to_dict())
    assert "ESCALATION CHAINS (0)" in out and "  none" in out
    assert "ACCOUNT TAKEOVER" not in out


def test_single_role_no_gating_is_told_it_learned_nothing():
    """The Cloudsplaining-equivalence notice: taint adds nothing to this shape."""
    raw = {
        "name": "shared",
        "account_id": "000000000000",
        "roles": [
            {
                "name": "only",
                "arn": "arn:aws:iam::000000000000:role/only",
                "identity_policies": [
                    {
                        "name": "p",
                        "statements": [
                            {"Sid": "S", "Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}
                        ],
                    }
                ],
            }
        ],
        "tools": [
            {"name": "a", "role": "only", "gating": "none", "tainted_inputs": ["q"]},
            {"name": "b", "role": "only", "gating": "none"},
        ],
    }
    report = analyze(deployment_from_dict(raw))
    assert any("taint propagation adds nothing" in n for n in report.notices)
    assert any("Cloudsplaining" in n for n in report.notices)


def test_no_taint_entrypoint_is_called_out():
    def untaint(raw):
        for t in raw["tools"]:
            t.pop("tainted_inputs", None)

    report = analyze(_deployment(untaint))
    assert any("No tool has tainted_inputs" in n for n in report.notices)
    assert not report.has_findings
