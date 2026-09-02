"""CI mode: ``fail_if`` gates and exit codes.

Findings and incompleteness are separate conditions with separate exit codes, and
``fail_if`` gates them independently. A run that found a chain **and** skipped a
``NotAction`` statement exits 3, not 1, so an incomplete analysis can never masquerade
as a clean one — or a clean one as merely incomplete.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import IRValidationError
from .report.schema import Report

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2
EXIT_FINDINGS_AND_INCOMPLETE = 3
EXIT_INPUT_ERROR = 4


@dataclass(frozen=True, slots=True)
class FailIf:
    reachable_actions_matching: tuple[str, ...] = ()
    escalation_chains_found: bool = False
    #: Fail if any chain reaches a principal in at most this many hops.
    max_chain_depth: int | None = None
    #: Fail closed when the analysis skipped something. Default on.
    unsupported_statements: bool = True

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> FailIf:
        raw = raw or {}
        known = {
            "reachable_actions_matching",
            "escalation_chains_found",
            "max_chain_depth",
            "unsupported_statements",
        }
        unknown = set(raw) - known
        if unknown:
            raise IRValidationError(
                f"fail_if: unknown keys {sorted(unknown)}; known: {sorted(known)}"
            )
        patterns = raw.get("reachable_actions_matching") or ()
        if isinstance(patterns, str):
            patterns = (patterns,)
        return cls(
            reachable_actions_matching=tuple(patterns),
            escalation_chains_found=bool(raw.get("escalation_chains_found", False)),
            max_chain_depth=raw.get("max_chain_depth"),
            unsupported_statements=bool(raw.get("unsupported_statements", True)),
        )


def load_fail_if(deployment_file: Path, policy_file: Path | None = None) -> FailIf:
    """``--policy`` wins; otherwise the ``fail_if`` block of agent.yaml; otherwise defaults."""
    if policy_file is not None:
        raw = yaml.safe_load(policy_file.read_text()) or {}
        return FailIf.from_dict(raw.get("fail_if", raw))
    raw = yaml.safe_load(deployment_file.read_text()) or {}
    return FailIf.from_dict(raw.get("fail_if"))


@dataclass
class Finding:
    """One thing that is wrong, plus every gate that objects to it.

    Grouped this way on purpose: a single escalation chain can trip both
    ``escalation_chains_found`` and ``max_chain_depth``, and reporting it once per gate
    turns three chains into six lines and invites the reader to think the count is broken.
    One finding, one line, with the gates it tripped named.
    """

    subject: str
    gates: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        return f"[{', '.join(self.gates)}] {self.subject}"


@dataclass
class Verdict:
    findings: list[Finding] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        code = EXIT_CLEAN
        if self.findings:
            code |= EXIT_FINDINGS
        if self.incomplete:
            code |= EXIT_INCOMPLETE
        return code


def evaluate(report: Report, fail_if: FailIf) -> Verdict:
    v = Verdict()
    by_subject: dict[str, Finding] = {}

    def trip(subject: str, gate: str) -> None:
        finding = by_subject.get(subject)
        if finding is None:
            finding = Finding(subject)
            by_subject[subject] = finding
            v.findings.append(finding)
        if gate not in finding.gates:
            finding.gates.append(gate)

    if fail_if.reachable_actions_matching:
        # One line per (pattern, principal, resource, provenance), not per action:
        # iam:* matching 180 actions is one fact, not 180.
        groups: dict[tuple, list[str]] = {}
        for cap in report.reachable_capabilities:
            for pattern in fail_if.reachable_actions_matching:
                if fnmatch.fnmatchcase(cap.action.lower(), pattern.lower()):
                    key = (pattern, cap.principal, cap.depth, cap.resource, tuple(cap.provenance))
                    groups.setdefault(key, []).append(cap.action)
                    break
        for (pattern, principal, depth, resource, provenance), actions in groups.items():
            sample = ", ".join(actions[:3]) + (", ..." if len(actions) > 3 else "")
            count = f"{len(actions)} actions" if len(actions) > 1 else actions[0]
            trip(
                f"{pattern!r} matches {count} on {resource} as {principal} (depth {depth}): "
                f"{sample}  <- {', '.join(provenance)}",
                "reachable_actions_matching",
            )

    chains = list(report.escalation_chains)
    if report.account_admin:
        chains.append(report.account_admin)
    for c in chains:
        within_depth = fail_if.max_chain_depth is not None and c.depth <= fail_if.max_chain_depth
        if not (fail_if.escalation_chains_found or within_depth):
            continue
        depth = f"depth {c.depth}"
        if within_depth:
            depth += f", within max_chain_depth {fail_if.max_chain_depth}"
        subject = f"chain {c.rule} -> {c.grants} ({depth})"
        if fail_if.escalation_chains_found:
            trip(subject, "escalation_chains_found")
        if within_depth:
            trip(subject, "max_chain_depth")

    if fail_if.unsupported_statements:
        for u in report.unsupported:
            v.incomplete.append(
                f"{u.kind} at {u.role}/{u.policy}#{u.sid}" + (f": {u.detail}" if u.detail else "")
            )

    v.incomplete = list(dict.fromkeys(v.incomplete))
    return v
