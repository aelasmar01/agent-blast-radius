from pathlib import Path

from agent_blast_radius.validate.corpus import load_fixture_corpus, load_managed_corpus
from agent_blast_radius.validate.preflight import INDEPENDENT_STRATA, preflight

FIXTURE = Path("fixtures/overprivileged-agent")
CORPUS = Path("validate/corpus.txt")


def test_preflight_passes_on_the_fixture():
    result = preflight(load_fixture_corpus(FIXTURE))
    assert result.checked > 0
    assert result.ok, "\n".join(str(m) for m in result.real)


def test_preflight_passes_on_the_managed_corpus():
    result = preflight(load_managed_corpus(CORPUS), per_policy=20)
    assert result.ok, "\n".join(str(m) for m in result.real[:10])
    assert sum(result.by_stratum[s] for s in INDEPENDENT_STRATA) > 50


def test_preflight_catches_a_broken_resolver(monkeypatch):
    """A resolver that says allow for everything must fail the independent strata."""
    from agent_blast_radius.validate import preflight as module

    monkeypatch.setattr(module, "resolver_decision", lambda *a, **k: "allow")
    result = module.preflight(load_fixture_corpus(FIXTURE))
    assert not result.ok
    assert all(m.is_independent for m in result.real)
    assert {m.draw.stratum for m in result.real} <= INDEPENDENT_STRATA


def test_allow_flagged_satisfies_an_allow_expectation():
    from agent_blast_radius.validate.preflight import _equivalent

    assert _equivalent("allow", "allow-flagged")
    assert not _equivalent("deny", "allow-flagged")
    assert not _equivalent("allow", "deny")
