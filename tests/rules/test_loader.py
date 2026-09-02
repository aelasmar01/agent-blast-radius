"""Rule-pack validation.

A malformed rule must fail at load time with a message naming the rule. A rule pack that
silently loads a broken rule produces findings nobody can audit.
"""

from __future__ import annotations

import pytest
import yaml

from agent_blast_radius.errors import IRValidationError
from agent_blast_radius.rules.loader import load_rules

BASE = {
    "id": "r1",
    "requires_actions": ["iam:PassRole"],
    "requires_facts": [],
    "grants": {"effective_principal": "{target}"},
    "source": "test",
    "notes": "why no facts",
    "variables": ["target"],
}


def _pack(tmp_path, *rules):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "rules": list(rules)}))
    return path


def test_bundled_pack_loads():
    pack = load_rules()
    assert pack.version == 1 and pack.rules
    assert pack.by_id("passrole-lambda-createfunction").grants_principal == "{target}"


def test_every_bundled_rule_declares_the_variables_it_uses():
    for rule in load_rules().rules:
        assert rule.all_variables  # raises if a clause references an undeclared variable


@pytest.mark.parametrize("missing", ["id", "requires_actions", "grants", "source"])
def test_missing_required_field(tmp_path, missing):
    rule = {k: v for k, v in BASE.items() if k != missing}
    with pytest.raises(IRValidationError, match=missing if missing != "id" else "missing"):
        load_rules(_pack(tmp_path, rule))


def test_grants_must_be_exactly_one_kind(tmp_path):
    both = {**BASE, "grants": {"effective_principal": "{target}", "all_actions": True}}
    with pytest.raises(IRValidationError, match="exactly one"):
        load_rules(_pack(tmp_path, both))
    neither = {**BASE, "grants": {}}
    with pytest.raises(IRValidationError, match="exactly one"):
        load_rules(_pack(tmp_path, neither))


def test_requires_facts_must_be_present(tmp_path):
    rule = {k: v for k, v in BASE.items() if k != "requires_facts"}
    with pytest.raises(IRValidationError, match="requires_facts must be present"):
        load_rules(_pack(tmp_path, rule))


def test_no_facts_and_no_notes_is_rejected(tmp_path):
    """An unconditioned rule has to say out loud why it needs no preconditions."""
    rule = {**BASE, "notes": ""}
    with pytest.raises(IRValidationError, match="no requires_facts and no notes"):
        load_rules(_pack(tmp_path, rule))


def test_unknown_fact_kind_is_rejected(tmp_path):
    rule = {**BASE, "requires_facts": [{"role_smells_bad": {"role": "{target}"}}]}
    with pytest.raises(IRValidationError, match="unknown fact kind"):
        load_rules(_pack(tmp_path, rule))


def test_fact_must_have_exactly_one_kind(tmp_path):
    rule = {**BASE, "requires_facts": [{"role_trusts_service": {}, "tool_backed_by_role": {}}]}
    with pytest.raises(IRValidationError, match="exactly one kind"):
        load_rules(_pack(tmp_path, rule))


def test_undeclared_variable_is_rejected(tmp_path):
    rule = {**BASE, "variables": [], "grants": {"effective_principal": "{ghost}"}}
    with pytest.raises(IRValidationError, match="undeclared variables"):
        load_rules(_pack(tmp_path, rule))


def test_self_is_implicit_and_need_not_be_declared(tmp_path):
    rule = {
        **BASE,
        "variables": [],
        "requires_actions": [{"action": "iam:PutRolePolicy", "resource": "{self}"}],
        "grants": {"all_actions": True},
    }
    assert load_rules(_pack(tmp_path, rule)).rules[0].all_variables == ("self",)


def test_duplicate_ids_are_rejected(tmp_path):
    with pytest.raises(IRValidationError, match="duplicate rule ids"):
        load_rules(_pack(tmp_path, BASE, dict(BASE)))
