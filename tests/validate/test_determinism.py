"""Seeded draws must be identical across processes.

`plan_draws` sorts the resolver's capability frozenset before sampling. If that sort key
is not a total order, ties fall back to frozenset iteration order, which Python randomizes
per process (PYTHONHASHSEED). The plan then differs run to run: two validation runs ask
different questions, and a recorded cassette fails to replay. Regression test for exactly
that — it runs the planner in subprocesses under different hash seeds.
"""

from __future__ import annotations

import json
import subprocess
import sys

SCRIPT = """
import json
from pathlib import Path
from agent_blast_radius.validate.corpus import load_managed_corpus, load_fixture_corpus
from agent_blast_radius.validate.run import build_plans
from agent_blast_radius.validate.simulate import batch
from agent_blast_radius.validate.cassette import _key

entries = load_fixture_corpus(Path("fixtures/overprivileged-agent")) + load_managed_corpus(
    Path("validate/corpus.txt")
)
plans = build_plans(entries, per_policy=40, seed=0)
draws = [
    (e.name, d.action, d.resource, d.context, d.stratum, d.expected)
    for e, plan in plans
    for d in plan.draws
]
keys = sorted(
    _key(r)
    for e, plan in plans
    for r in batch(e.documents, plan.draws, e.resource_policy_map, e.caller_arn)
)
print(json.dumps({"draws": draws, "keys": keys}))
"""


def _plan_under(seed: str) -> dict:
    out = subprocess.run(
        [sys.executable, "-c", SCRIPT],
        capture_output=True,
        text=True,
        check=True,
        env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"},
    )
    return json.loads(out.stdout)


def test_draw_plan_is_identical_across_hash_seeds():
    a = _plan_under("1")
    b = _plan_under("12345")
    assert a["draws"] == b["draws"]


def test_request_keys_are_identical_across_hash_seeds():
    """The property a recorded cassette depends on: same run, same request keys."""
    assert _plan_under("7")["keys"] == _plan_under("999")["keys"]


def test_capability_order_is_total():
    """Two capabilities differing only in conditions must still order deterministically."""
    from agent_blast_radius.ir import Capability, Condition
    from agent_blast_radius.validate.draws import _draw_order

    a = Capability("s3:GetObject", "*", (Condition("StringEquals", "k", ("v",)),))
    b = Capability("s3:GetObject", "*", (Condition("StringEquals", "k", ("w",)),))
    assert _draw_order(a) != _draw_order(b)
    assert sorted([a, b], key=_draw_order) == sorted([b, a], key=_draw_order)
