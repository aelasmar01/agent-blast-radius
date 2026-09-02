"""The confusion matrix — the artifact this harness exists to produce."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .draws import Draw

RESOLVER_ROWS = ("allow", "allow-flagged", "deny", "unsupported")
AWS_COLS = ("allowed", "explicitDeny", "implicitDeny")


@dataclass(frozen=True, slots=True)
class Outcome:
    policy: str
    group: str
    draw: Draw
    resolver: str
    aws: str

    @property
    def is_silent_under_report(self) -> bool:
        """The cell that matters: we said no, AWS said yes."""
        return self.resolver == "deny" and self.aws == "allowed"

    @property
    def is_over_report(self) -> bool:
        return self.resolver == "allow" and self.aws != "allowed"


@dataclass
class Matrix:
    outcomes: list[Outcome] = field(default_factory=list)

    def add(self, outcome: Outcome) -> None:
        self.outcomes.append(outcome)

    def counts(self, policy: str | None = None) -> Counter:
        return Counter(
            (o.resolver, o.aws) for o in self.outcomes if policy is None or o.policy == policy
        )

    def policies(self) -> list[str]:
        seen: dict[str, None] = {}
        for o in self.outcomes:
            seen.setdefault(o.policy)
        return list(seen)

    @property
    def under_reports(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.is_silent_under_report]

    @property
    def over_reports(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.is_over_report]

    def render_table(self, policy: str | None = None) -> str:
        c = self.counts(policy)
        lines = [
            "| resolver \\ AWS | " + " | ".join(AWS_COLS) + " |",
            "|---|" + "---:|" * len(AWS_COLS),
        ]
        for row in RESOLVER_ROWS:
            cells = []
            for col in AWS_COLS:
                n = c.get((row, col), 0)
                mark = " **⚠**" if (row, col) == ("deny", "allowed") and n else ""
                cells.append(f"{n}{mark}")
            lines.append(f"| {row} | " + " | ".join(cells) + " |")
        return "\n".join(lines)

    def render_markdown(self, *, dataset_version: str, title: str) -> str:
        parts = [
            f"# {title}",
            "",
            f"Resolver dataset commit: `{dataset_version}`",
            f"Draws: {len(self.outcomes)}",
            "",
        ]
        parts += ["## Aggregate", "", self.render_table(), ""]
        parts += [
            "Rows are the resolver's claim; columns are `iam:SimulateCustomPolicy`. "
            "`deny / allowed` is the silent under-report — the only cell that is a bug by "
            "definition. `allow / *Deny` is over-report (noise). `allow-flagged` and "
            "`unsupported` rows are the resolver declining to answer; their spread across "
            "columns measures how much precision that costs.",
            "",
        ]
        parts += ["## Silent under-reports (resolver=deny, AWS=allowed)", ""]
        if not self.under_reports:
            parts.append("None.")
        else:
            parts += ["| policy | action | resource | context | stratum |", "|---|---|---|---|---|"]
            for o in self.under_reports:
                parts.append(
                    f"| {o.policy} | `{o.draw.action}` | `{o.draw.resource or '*'}` | "
                    f"`{dict(o.draw.context) or ''}` | {o.draw.stratum} |"
                )
        parts += ["", "## Over-reports (resolver=allow, AWS denied)", ""]
        if not self.over_reports:
            parts.append("None.")
        else:
            parts += [
                "| policy | action | resource | context | stratum | AWS |",
                "|---|---|---|---|---|---|",
            ]
            for o in self.over_reports:
                parts.append(
                    f"| {o.policy} | `{o.draw.action}` | `{o.draw.resource or '*'}` | "
                    f"`{dict(o.draw.context) or ''}` | {o.draw.stratum} | {o.aws} |"
                )
        parts += ["", "## Per policy", ""]
        for policy in self.policies():
            group = next(o.group for o in self.outcomes if o.policy == policy)
            parts += [f"### {policy} `[{group}]`", "", self.render_table(policy), ""]
        return "\n".join(parts)
