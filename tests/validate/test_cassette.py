from pathlib import Path

import pytest

from agent_blast_radius.validate.cassette import RecordingSimulator, ReplaySimulator
from agent_blast_radius.validate.corpus import load_fixture_corpus
from agent_blast_radius.validate.run import run
from agent_blast_radius.validate.simulate import FakeSimulator, Request

FIXTURE = Path("fixtures/overprivileged-agent")


def test_record_then_replay_reproduces_the_matrix(tmp_path):
    entries = load_fixture_corpus(FIXTURE)
    live = FakeSimulator(lambda a, r, c: "allowed" if a.startswith("s3:") else "implicitDeny")
    recorder = RecordingSimulator(live, tmp_path / "cassette.json")
    devnull = open("/dev/null", "w")
    first = run(entries, recorder, per_policy=20, log=devnull)
    path = recorder.save()

    replayed = run(entries, ReplaySimulator(path), per_policy=20, log=devnull)
    assert [(o.policy, o.draw.action, o.aws) for o in replayed.outcomes] == [
        (o.policy, o.draw.action, o.aws) for o in first.outcomes
    ]
    assert replayed.render_table() == first.render_table()


def test_replay_refuses_to_guess_an_unrecorded_request(tmp_path):
    path = tmp_path / "cassette.json"
    RecordingSimulator(FakeSimulator(lambda a, r, c: "allowed"), path).save()
    with pytest.raises(KeyError, match="never guess"):
        ReplaySimulator(path).simulate(Request(("{}",), ("s3:GetObject",), None, ()))
