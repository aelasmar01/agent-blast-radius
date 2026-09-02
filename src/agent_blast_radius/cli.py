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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
