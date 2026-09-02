"""Tool-level taint propagation.

A tool is reachable from attacker-controlled input iff it is ungated and either takes
tainted input directly or some reachable tool's output re-enters the model's context.
That second clause is the whole second-order-taint model: one flag, one extra fixpoint
iteration, and the mechanism most people miss.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ir import Deployment, Gating


@dataclass(frozen=True, slots=True)
class Reach:
    #: tool name -> why it is reachable
    reachable: dict[str, str] = field(default_factory=dict)
    #: tool name -> why it is not
    unreachable: dict[str, str] = field(default_factory=dict)

    @property
    def roles(self) -> frozenset[str]:
        return frozenset(self._roles)

    _roles: tuple[str, ...] = ()

    @property
    def is_degenerate(self) -> bool:
        """True when taint adds nothing: every tool is reachable and nothing is gated."""
        return not self.unreachable and bool(self.reachable)


def compute_reach(deployment: Deployment) -> Reach:
    reachable: dict[str, str] = {}
    unreachable: dict[str, str] = {}
    tools = {t.name: t for t in deployment.tools}

    for t in deployment.tools:
        if t.gating is not Gating.NONE:
            unreachable[t.name] = f"gated: {t.gating.value}"
        elif t.is_taint_entrypoint:
            reachable[t.name] = "tainted input: " + ", ".join(sorted(t.tainted_inputs))

    changed = True
    while changed:
        changed = False
        feeders = [n for n in reachable if tools[n].returns_external_data]
        if not feeders:
            break
        for t in deployment.tools:
            if t.name in reachable or t.name in unreachable:
                continue
            reachable[t.name] = (
                f"output of {', '.join(sorted(feeders))} re-enters the model context"
            )
            changed = True

    for t in deployment.tools:
        if t.name not in reachable and t.name not in unreachable:
            unreachable[t.name] = (
                "no taint path: not an entrypoint and no reachable tool returns external data"
            )

    roles = tuple(sorted({tools[n].role for n in reachable}))
    return Reach(reachable=reachable, unreachable=unreachable, _roles=roles)
