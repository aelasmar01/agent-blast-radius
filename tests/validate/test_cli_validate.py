"""End-to-end paths of the `validate` subcommand that need no AWS account."""

from __future__ import annotations

import json
from pathlib import Path

from agent_blast_radius.ci import EXIT_CLEAN, EXIT_FINDINGS, EXIT_INPUT_ERROR
from agent_blast_radius.cli import main
from agent_blast_radius.validate.cassette import RecordingSimulator
from agent_blast_radius.validate.corpus import load_fixture_corpus
from agent_blast_radius.validate.draws import resolver_decision
from agent_blast_radius.iam.resolver import resolve_role
from agent_blast_radius.validate.run import run
from agent_blast_radius.validate.simulate import FakeSimulator

FIXTURE = "fixtures/overprivileged-agent"
CORPUS = "validate/corpus.txt"


def test_dry_run_needs_no_credentials(capsys):
    assert main(["validate", "--fixture", FIXTURE, "--corpus", CORPUS, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "SimulateCustomPolicy calls" in out
    assert "incident-response-role" in out


def test_preflight_passes_and_exits_clean(capsys):
    assert main(["validate", "--fixture", FIXTURE, "--corpus", CORPUS, "--preflight"]) == EXIT_CLEAN
    err = capsys.readouterr().err
    assert "no mismatches on the" in err
    assert "lint pass, not validation" in err


def test_preflight_failure_is_reported_and_exits_nonzero(capsys, monkeypatch):
    from agent_blast_radius.validate import preflight as module

    monkeypatch.setattr(module, "resolver_decision", lambda *a, **k: "allow")
    assert (
        main(["validate", "--fixture", FIXTURE, "--corpus", CORPUS, "--preflight"]) == EXIT_FINDINGS
    )
    err = capsys.readouterr().err
    assert "MISMATCH(ES) on independently-derived expectations" in err


def test_empty_corpus_is_an_input_error(capsys):
    assert main(["validate", "--corpus", "", "--dry-run"]) == EXIT_INPUT_ERROR
    assert "nothing to validate" in capsys.readouterr().err


def test_replay_produces_results_without_aws(tmp_path, capsys):
    # Record against a fake, then drive the CLI purely from the cassette.
    entries = load_fixture_corpus(Path(FIXTURE))
    resolutions = {e.name: resolve_role(e.role) for e in entries}
    cassette = tmp_path / "c.json"
    for entry in entries:
        res = resolutions[entry.name]
        rec = RecordingSimulator(
            FakeSimulator(
                lambda a, r, c, res=res: (
                    "allowed" if resolver_decision(res, a, r, c) == "allow" else "implicitDeny"
                )
            ),
            cassette,
        )
        run([entry], rec, per_policy=40, log=open("/dev/null", "w"))
        existing = json.loads(cassette.read_text())["exchanges"] if cassette.exists() else {}
        rec._entries = {**existing, **rec._entries}
        rec.save()

    out_dir = tmp_path / "results"
    code = main(
        [
            "validate",
            "--fixture",
            FIXTURE,
            "--corpus",
            "",
            "--replay",
            str(cassette),
            "--out",
            str(out_dir),
        ]
    )
    assert code == 0
    err = capsys.readouterr().err
    assert "replaying" in err and "silent under-reports" in err
    written = sorted(out_dir.glob("*.md"))
    assert written, "no results file written"
    body = written[0].read_text()
    assert "## Aggregate" in body and "resolver \\ AWS" in body
    assert "## Silent under-reports" in body
