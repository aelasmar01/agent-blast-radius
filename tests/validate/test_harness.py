from pathlib import Path

import pytest

from agent_blast_radius.iam.resolver import resolve_role
from agent_blast_radius.validate.corpus import load_fixture_corpus, load_managed_corpus
from agent_blast_radius.validate.draws import STRATA_DENY, plan_draws, resolver_decision
from agent_blast_radius.validate.matrix import Matrix, Outcome
from agent_blast_radius.validate.run import dry_run, run
from agent_blast_radius.validate.simulate import ACTIONS_PER_CALL, FakeSimulator, batch

FIXTURE = Path("fixtures/overprivileged-agent")
CORPUS = Path("validate/corpus.txt")


@pytest.fixture(scope="module")
def fixture_entries():
    return load_fixture_corpus(FIXTURE)


@pytest.fixture(scope="module")
def corpus_entries():
    return load_managed_corpus(CORPUS)


def test_corpus_loads_and_is_diverse(corpus_entries):
    assert 40 <= len(corpus_entries) <= 50
    groups = {e.group for e in corpus_entries}
    assert {
        "broad-wildcard",
        "resource-constrained",
        "condition-heavy",
        "explicit-deny",
        "notaction",
    } <= groups


def test_draws_are_deterministic_and_stratified(fixture_entries):
    entry = next(e for e in fixture_entries if e.name == "agent-execution-role")
    res = resolve_role(entry.role)
    a = plan_draws(entry.role, res, per_policy=40, seed=0)
    b = plan_draws(entry.role, res, per_policy=40, seed=0)
    assert [d.action for d in a.draws] == [d.action for d in b.draws]
    strata = a.by_stratum()
    assert "allow-unconditional" in strata
    assert "explicit-deny" in strata  # NoDirectSecretAccess
    assert "wrong-resource" in strata  # PassRole on role/*
    assert set(strata) - set(("allow-unconditional", "allow-conditioned", "allow-flagged")) <= set(
        STRATA_DENY
    )


def test_wrong_resource_draws_do_not_match_any_granted_pattern(fixture_entries):
    entry = next(e for e in fixture_entries if e.name == "agent-execution-role")
    res = resolve_role(entry.role)
    for d in plan_draws(entry.role, res).draws:
        if d.stratum == "wrong-resource":
            assert resolver_decision(res, d.action, d.resource, d.context_dict) == "deny"
            assert d.resource.startswith("arn:aws:iam::")


def test_notaction_policy_yields_unsupported_draws(corpus_entries):
    entry = next(e for e in corpus_entries if e.name == "PowerUserAccess")
    res = resolve_role(entry.role)
    plan = plan_draws(entry.role, res)
    assert any(d.stratum == "notaction-excluded" for d in plan.draws)
    assert resolver_decision(res, "iam:CreateUser", None, {}) == "unsupported"


def test_resolver_decision_semantics(fixture_entries):
    entry = next(e for e in fixture_entries if e.name == "ticket-reader-role")
    res = resolve_role(entry.role)
    assert (
        resolver_decision(res, "s3:GetObject", "arn:aws:s3:::support-tickets/a.json", {}) == "allow"
    )
    assert resolver_decision(res, "s3:GetObject", "arn:aws:s3:::other/a.json", {}) == "deny"
    # No ResourceArns means AWS evaluates against '*', which a scoped grant does not cover.
    assert resolver_decision(res, "s3:GetObject", None, {}) == "deny"


def test_batching_groups_by_resource_and_context(fixture_entries):
    entry = next(e for e in fixture_entries if e.name == "incident-response-role")
    plan = plan_draws(entry.role, resolve_role(entry.role), per_policy=60)
    requests = batch(entry.documents, plan.draws)
    assert all(len(r.actions) <= ACTIONS_PER_CALL for r in requests)
    covered = {(a, r.resource, r.context) for r in requests for a in r.actions}
    assert {(d.action, d.resource, d.context) for d in plan.draws} <= covered


def test_matrix_places_the_cells_that_matter():
    m = Matrix()
    from agent_blast_radius.validate.draws import Draw

    d = Draw("s3:GetObject", None, (), "uniform", "deny")
    m.add(Outcome("P", "g", d, "deny", "allowed"))
    m.add(Outcome("P", "g", d, "allow", "implicitDeny"))
    m.add(Outcome("P", "g", d, "allow", "allowed"))
    assert len(m.under_reports) == 1 and len(m.over_reports) == 1
    md = m.render_markdown(dataset_version="abc", title="t")
    assert "**⚠**" in md and "## Silent under-reports" in md


def test_run_with_agreeing_fake_has_no_under_reports(fixture_entries):
    # A fake AWS that agrees with the resolver by construction: proves the plumbing,
    # and that draw -> request -> verdict -> outcome round-trips every draw.
    resolutions = {e.name: resolve_role(e.role) for e in fixture_entries}
    outcomes = []
    for entry in fixture_entries:
        res = resolutions[entry.name]
        sim = FakeSimulator(
            lambda a, r, c, res=res: (
                "allowed" if resolver_decision(res, a, r, c) == "allow" else "implicitDeny"
            )
        )
        matrix = run([entry], sim, per_policy=20, log=open("/dev/null", "w"))
        outcomes += matrix.outcomes
        assert all(o.aws != "missing" for o in matrix.outcomes)
        assert not matrix.under_reports
    assert outcomes


def test_dry_run_reports_call_budget(fixture_entries, capsys):
    calls = dry_run(fixture_entries, per_policy=40, seed=0)
    out = capsys.readouterr().out
    assert "SimulateCustomPolicy calls" in out
    assert 0 < calls < 200
