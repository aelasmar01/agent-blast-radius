# Intentional divergences from `iam:SimulateCustomPolicy`

Every entry here is a place where the resolver knowingly answers differently from AWS's
own engine. Each one is either the conservative direction (over-report, flagged) or a
declared refusal (`unsupported`). A divergence that is neither belongs in the bug
tracker, not in this file.

Numbered so the validation results can cite them. Populated as the harness surfaces
them; the first live run is the source for the initial set.

| # | Construct | Resolver behaviour | Direction | Why |
|---|---|---|---|---|
| D1a | `Allow` + `NotAction` | **Inverted**: granted set is every known action minus the exclusions. Recorded once per statement as a `notaction_inverted` assumption | Exact, bounded by snapshot completeness | The action universe is finite and enumerable, so inversion is exact. Refusing instead made the tool useless on `PowerUserAccess` — 100% refusal on one of the most widely attached policies in AWS. Verified against live authorization decisions: [2026-09-01 probe](../validate/results/2026-09-01-live-authorization-probe.md) |
| D1b | `Deny` + `NotAction`, and any `NotResource` | Statement skipped, recorded as `unsupported` | Refusal | Inverting a `Deny` on a stale snapshot shrinks the denied set and hands back capabilities AWS blocks — a false negative. `NotResource` cannot be inverted at all: ARNs are not enumerable |
| D2 | `Null`, `StringNotEquals`, `ArnEquals`, `*IfExists`, `ForAnyValue:*`, `ForAllValues:*`, numeric/date operators | Capability kept, operator recorded in residue, reported as *unconstrained but flagged* | Over-report | Only four operators are modeled in v1 (`StringEquals`, `StringLike`, `ArnLike`, `Bool`). `Null` is the third most common operator in the managed-policy snapshot (509 uses) and is the first candidate to add. |
| D3 | Conditional `Deny` | Never removes a capability; flags it `deny-conditional` | Over-report | A Deny we cannot prove must never produce a false negative |
| D4 | Partial-overlap `Deny` (deny pattern narrower than the allow pattern) | Capability kept, flagged `deny-partial` | Over-report | Representing the difference of two globs needs set splitting; flagging is honest and cheap |
| D5 | Simulation with no `ResourceArns` | Resolver answers `deny` unless a capability is on `*` | Matches AWS | AWS evaluates against `*`; recorded here because it is easy to get wrong the other way |
| D6 | Unknown action (not in the snapshot) | Kept literally, recorded as `unknown_action` | Over-report + flag | A new service must not vanish from the report because the snapshot is stale |

## Before the first live run

`agent-blast-radius validate --preflight` passes on all independently-derived draws
across the 44-policy corpus. That is a lint result, not a validation result — it cannot
find a misunderstanding of IAM semantics, because it shares them. The rows above are
predictions of where the live run will diverge, not observations. Replace them with
observed evidence after the first run.

## How to add an entry

1. Find the row in `validate/results/<date>.md` — usually the "over-reports" table or
   the `allow-flagged` / `unsupported` rows.
2. Reproduce with a single-statement policy in `tests/iam/`.
3. Decide: bug (fix the resolver) or intentional (add a row here, cite it from the test).
