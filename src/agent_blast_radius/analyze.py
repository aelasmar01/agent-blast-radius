"""One call from a deployment to a report. The CLI and tests both go through this."""

from __future__ import annotations

from pathlib import Path

from .iam.resolver import resolve_deployment
from .ir import Deployment
from .reach import compute_reach
from .report.schema import Report, build_report
from .rules.engine import escalate
from .rules.loader import RulePack, load_rules


def analyze(deployment: Deployment, *, rules: Path | None = None) -> Report:
    pack: RulePack = load_rules(rules)
    resolutions = resolve_deployment(deployment)
    reach = compute_reach(deployment)
    escalation = escalate(deployment, resolutions, reach.roles, pack)
    return build_report(deployment, resolutions, reach, escalation, pack)
