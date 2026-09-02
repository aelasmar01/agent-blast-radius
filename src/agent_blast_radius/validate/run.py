"""Harness driver: corpus → draws → simulate → matrix → results files."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from ..iam import actions as action_db
from ..iam.resolver import resolve_role
from .corpus import CorpusEntry, load_fixture_corpus, load_managed_corpus
from .draws import DrawPlan, plan_draws, resolver_decision
from .matrix import Matrix, Outcome
from .simulate import Simulator, batch


def build_plans(
    entries: list[CorpusEntry], *, per_policy: int, seed: int
) -> list[tuple[CorpusEntry, DrawPlan]]:
    plans = []
    for entry in entries:
        resolution = resolve_role(entry.role)
        plans.append((entry, plan_draws(entry.role, resolution, per_policy=per_policy, seed=seed)))
    return plans


def run(
    entries: list[CorpusEntry],
    simulator: Simulator,
    *,
    per_policy: int = 40,
    seed: int = 0,
    log=None,
) -> Matrix:
    log = log or sys.stderr
    matrix = Matrix()
    for entry, plan in build_plans(entries, per_policy=per_policy, seed=seed):
        resolution = resolve_role(entry.role)
        decisions: dict[tuple, str] = {}
        for request in batch(entry.documents, plan.draws):
            verdicts = simulator.simulate(request)
            for action, verdict in verdicts.items():
                decisions[(action, request.resource, request.context)] = verdict
        for draw in plan.draws:
            aws = decisions.get((draw.action, draw.resource, draw.context), "missing")
            ours = resolver_decision(resolution, draw.action, draw.resource, draw.context_dict)
            matrix.add(Outcome(entry.name, entry.group, draw, ours, aws))
        under = sum(
            1 for o in matrix.outcomes if o.policy == entry.name and o.is_silent_under_report
        )
        print(f"  {entry.name:60s} draws={len(plan.draws):3d} under-reports={under}", file=log)
    return matrix


def dry_run(entries: list[CorpusEntry], *, per_policy: int, seed: int, out=None) -> int:
    out = out or sys.stdout
    total_draws = 0
    total_calls = 0
    for entry, plan in build_plans(entries, per_policy=per_policy, seed=seed):
        calls = len(batch(entry.documents, plan.draws))
        total_draws += len(plan.draws)
        total_calls += calls
        strata = " ".join(f"{k}={v}" for k, v in sorted(plan.by_stratum().items()))
        print(
            f"{entry.name:60s} [{entry.group}] draws={len(plan.draws):3d} calls={calls:3d}  {strata}",
            file=out,
        )
    print(
        f"\n{len(entries)} policies, {total_draws} draws, {total_calls} SimulateCustomPolicy calls",
        file=out,
    )
    print(f"at ~5 calls/s: ~{total_calls / 5:.0f}s of API time", file=out)
    return total_calls


def write_results(matrix: Matrix, out_dir: Path, *, title: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y-%m-%d")
    md = out_dir / f"{stamp}.md"
    js = out_dir / f"{stamp}.json"
    md.write_text(matrix.render_markdown(dataset_version=action_db.dataset_version(), title=title))
    js.write_text(
        json.dumps(
            {
                "dataset_version": action_db.dataset_version(),
                "generated": datetime.now(UTC).isoformat(),
                "outcomes": [
                    {
                        **asdict(o.draw),
                        "policy": o.policy,
                        "group": o.group,
                        "resolver": o.resolver,
                        "aws": o.aws,
                    }
                    for o in matrix.outcomes
                ],
            },
            indent=1,
        )
    )
    return md, js


def load_corpus(corpus_path: Path | None, fixture_path: Path | None) -> list[CorpusEntry]:
    entries: list[CorpusEntry] = []
    if fixture_path:
        entries += load_fixture_corpus(fixture_path)
    if corpus_path:
        entries += load_managed_corpus(corpus_path)
    return entries
