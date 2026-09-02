# Intentional divergences from `iam:SimulateCustomPolicy`

Every entry here is a place where the resolver knowingly answers differently from AWS's
own engine. Each one is either the conservative direction (over-report, flagged) or a
declared refusal (`unsupported`). A divergence that is neither belongs in the bug
tracker, not in this file.

Numbered so the validation results can cite them. Populated as the harness surfaces
them; the first live run is the source for the initial set.

| # | Construct | Resolver behaviour | Direction | Why |
|---|---|---|---|---|
| D1 | `NotAction` / `NotResource` | Statement skipped, recorded as `unsupported`; draws inside the excluded set land in the `unsupported` row | Refusal | Inverting the set logic is a silent under-report risk if done imperfectly; refusing visibly is defensible |
| D2 | `Null`, `StringNotEquals`, `ArnEquals`, `*IfExists`, `ForAnyValue:*`, `ForAllValues:*`, numeric/date operators | Capability kept, operator recorded in residue, reported as *unconstrained but flagged* | Over-report | Only four operators are modeled in v1 (`StringEquals`, `StringLike`, `ArnLike`, `Bool`). `Null` is the third most common operator in the managed-policy snapshot (509 uses) and is the first candidate to add. |
| D3 | Conditional `Deny` | Never removes a capability; flags it `deny-conditional` | Over-report | A Deny we cannot prove must never produce a false negative |
| D4 | Partial-overlap `Deny` (deny pattern narrower than the allow pattern) | Capability kept, flagged `deny-partial` | Over-report | Representing the difference of two globs needs set splitting; flagging is honest and cheap |
| D5 | Simulation with no `ResourceArns` | Resolver answers `deny` unless a capability is on `*` | Matches AWS | AWS evaluates against `*`; recorded here because it is easy to get wrong the other way |
| D6 | Unknown action (not in the snapshot) | Kept literally, recorded as `unknown_action` | Over-report + flag | A new service must not vanish from the report because the snapshot is stale |

## How to add an entry

1. Find the row in `validate/results/<date>.md` — usually the "over-reports" table or
   the `allow-flagged` / `unsupported` rows.
2. Reproduce with a single-statement policy in `tests/iam/`.
3. Decide: bug (fix the resolver) or intentional (add a row here, cite it from the test).
