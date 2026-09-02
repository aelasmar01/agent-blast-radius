"""Command-line entry point.

``scan`` is the only command that matters. Today it loads and validates a deployment
and prints the inventory; the resolver and reachability engine are not implemented, so
it exits non-zero rather than returning a clean bill of health it has not earned.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from . import __version__
from .errors import AgentBlastRadiusError
from .ir import Deployment, Gating, deployment_from_dict

#: Loaded and validated the deployment, but analysis is not implemented.
EXIT_INCOMPLETE = 2
#: The input could not be loaded or is inconsistent.
EXIT_ERROR = 3

DEPLOYMENT_FILENAMES = ("agent.yaml", "agent.yml")


def load_deployment(target: Path) -> Deployment:
    path = target
    if target.is_dir():
        for name in DEPLOYMENT_FILENAMES:
            candidate = target / name
            if candidate.exists():
                path = candidate
                break
        else:
            raise AgentBlastRadiusError(f"no {' or '.join(DEPLOYMENT_FILENAMES)} found in {target}")
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise AgentBlastRadiusError(f"{path}: expected a mapping at the top level")
    return deployment_from_dict(raw)


def render_inventory(deployment: Deployment, out) -> None:
    print(f"deployment: {deployment.name}  (IR schema {deployment.schema_version})", file=out)
    print(f"account:    {deployment.account_id or '<unspecified>'}", file=out)
    print(f"\ntools ({len(deployment.tools)}):", file=out)
    for tool in deployment.tools:
        marks = []
        if tool.is_taint_entrypoint:
            marks.append("tainted-input:" + ",".join(sorted(tool.tainted_inputs)))
        if tool.returns_external_data:
            marks.append("returns-external-data")
        if tool.gating is not Gating.NONE:
            marks.append(f"gated:{tool.gating.value}")
        suffix = ("  [" + " ".join(marks) + "]") if marks else ""
        print(f"  - {tool.name}  role={tool.role}{suffix}", file=out)
    print(f"\nroles ({len(deployment.roles)}):", file=out)
    for role in deployment.roles:
        trusted = ",".join(sorted(role.trust_policy.service_principals)) or "<none parsed>"
        statements = sum(len(p.statements) for p in role.identity_policies)
        print(
            f"  - {role.name}  policies={len(role.identity_policies)} "
            f"statements={statements} trusts={trusted}",
            file=out,
        )


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        deployment = load_deployment(Path(args.target))
    except AgentBlastRadiusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    render_inventory(deployment, sys.stdout)
    print(
        "\nanalysis not implemented: the IAM resolver, taint propagation, and "
        "reachability fixpoint are not built yet, so this run reports no findings "
        "because it computed none — not because none exist. Exiting non-zero.",
        file=sys.stderr,
    )
    return EXIT_INCOMPLETE


def cmd_validate(args: argparse.Namespace) -> int:
    from .validate.run import dry_run, load_corpus, run, write_results

    entries = load_corpus(
        Path(args.corpus) if args.corpus else None,
        Path(args.fixture) if args.fixture else None,
    )
    if not entries:
        print("error: nothing to validate; pass --corpus and/or --fixture", file=sys.stderr)
        return EXIT_ERROR
    if args.dry_run:
        dry_run(entries, per_policy=args.per_policy, seed=args.seed)
        return 0
    try:
        from .validate.simulate import BotoSimulator
    except ImportError:
        print(
            "error: boto3 is required for a live run; install agent-blast-radius[validate]",
            file=sys.stderr,
        )
        return EXIT_ERROR
    simulator = BotoSimulator(calls_per_second=args.rate)
    print(f"validating {len(entries)} policies against iam:SimulateCustomPolicy", file=sys.stderr)
    matrix = run(entries, simulator, per_policy=args.per_policy, seed=args.seed)
    md, js = write_results(matrix, Path(args.out), title="Resolver vs iam:SimulateCustomPolicy")
    print(
        f"\n{len(matrix.under_reports)} silent under-reports, {len(matrix.over_reports)} over-reports",
        file=sys.stderr,
    )
    print(f"wrote {md} and {js} ({simulator.calls} API calls)", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-blast-radius",
        description=(
            "Compute the AWS actions an attacker who controls model input can reach "
            "through an agent's tools."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyze a deployment directory or agent.yaml")
    scan.add_argument("target", help="directory containing agent.yaml, or the file itself")
    scan.set_defaults(func=cmd_scan)

    validate = sub.add_parser(
        "validate",
        help="differential-test the resolver against iam:SimulateCustomPolicy",
        description=(
            "Draws stratified, boundary-weighted test cases from a corpus of managed policies "
            "and/or a fixture's roles, asks AWS, and writes a confusion matrix. Needs only "
            "iam:SimulateCustomPolicy; creates nothing. --dry-run needs no credentials."
        ),
    )
    validate.add_argument("--corpus", default="validate/corpus.txt", help="managed policy ARN list")
    validate.add_argument("--fixture", default=None, help="deployment dir whose roles to include")
    validate.add_argument("--out", default="validate/results", help="results directory")
    validate.add_argument(
        "--per-policy", type=int, default=40, help="draws per policy (half allow, half deny)"
    )
    validate.add_argument("--seed", type=int, default=0)
    validate.add_argument(
        "--rate", type=float, default=5.0, help="max SimulateCustomPolicy calls per second"
    )
    validate.add_argument(
        "--dry-run", action="store_true", help="print the draw plan and call budget only"
    )
    validate.set_defaults(func=cmd_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
