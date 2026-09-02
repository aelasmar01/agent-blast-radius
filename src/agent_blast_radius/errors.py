"""Error types.

The analyzer fails loudly rather than under-reporting. A silent under-report in a
security tool is worse than a crash, because it is indistinguishable from a clean bill
of health.
"""


class AgentBlastRadiusError(Exception):
    """Base class for every error this package raises deliberately."""


class UnsupportedPolicyConstruct(AgentBlastRadiusError):
    """A policy uses a construct the resolver refuses to approximate.

    ``NotAction`` and ``NotResource`` invert the set logic. Approximating them either
    over-reports (noise) or under-reports (a missed finding presented as safety). On the
    scan path the resolver records these as :class:`~agent_blast_radius.ir.Unsupported`
    and continues; this exception exists for callers that want strict mode.
    """

    def __init__(self, construct: str, statement_id: str, policy_name: str) -> None:
        self.construct = construct
        self.statement_id = statement_id
        self.policy_name = policy_name
        super().__init__(
            f"{policy_name}: statement {statement_id!r} uses {construct}, which this "
            f"analyzer refuses to approximate. Rewrite the statement or exclude the "
            f"policy explicitly."
        )


class IRValidationError(AgentBlastRadiusError):
    """A deployment description is malformed or internally inconsistent."""
