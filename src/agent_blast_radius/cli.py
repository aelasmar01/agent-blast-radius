"""Command-line entry point.

``scan`` analyzes a deployment and exits with a code CI can gate on:

    0  clean: no gated findings, nothing unsupported
    1  findings (a fail_if gate tripped)
    2  incomplete: the analysis skipped something it refuses to approximate
    3  both
    4  input error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyze import analyze
from .ci import EXIT_INPUT_ERROR, evaluate, load_fail_if
from .errors import AgentBlastRadiusError
from .loaders import find_deployment_file, load_deployment
from .report.terminal import render

EXIT_ERROR = EXIT_INPUT_ERROR


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        target = Path(args.target)
        deployment_file = find_deployment_file(target)
        deployment = load_deployment(target)
        fail_if = load_fail_if(deployment_file, Path(args.policy) if args.policy else None)
        report = analyze(deployment, rules=Path(args.rules) if args.rules else None)
    except AgentBlastRadiusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    payload = report.to_dict()
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=1))
    if not args.quiet:
        print(render(payload))

    verdict = evaluate(report, fail_if)
    if verdict.findings or verdict.incomplete:
        print("", file=sys.stderr)
    if verdict.findings:
        print(f"FAIL: {len(verdict.findings)} finding(s) tripped fail_if:", file=sys.stderr)
        for line in verdict.findings:
            print(f"  - {line}", file=sys.stderr)
    if verdict.incomplete:
        print(f"INCOMPLETE: {len(verdict.incomplete)} unsupported construct(s):", file=sys.stderr)
        for line in verdict.incomplete:
            print(f"  - {line}", file=sys.stderr)
    return verdict.exit_code


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
    under, over = len(matrix.under_reports), len(matrix.over_reports)
    print(f"\n{under} silent under-reports, {over} over-reports", file=sys.stderr)
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
    scan.add_argument("--json", metavar="PATH", help="also write the versioned JSON report here")
    scan.add_argument("--policy", metavar="PATH", help="fail_if policy file (overrides agent.yaml)")
    scan.add_argument("--rules", metavar="PATH", help="alternative rule pack")
    scan.add_argument(
        "--quiet", "-q", action="store_true", help="no terminal report, exit code only"
    )
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
