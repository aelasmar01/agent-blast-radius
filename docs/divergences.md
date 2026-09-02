# Divergences from `iam:SimulateCustomPolicy`

Observed, not predicted. Source: [`validate/results/2026-09-02.md`](../validate/results/2026-09-02.md)
— 1,148 stratified draws over 44 AWS managed policies and the fixture's five roles, 232 API
calls against account 234612058514, dataset commit `8e8e0df0ce50`. The committed cassette
[`validate/cassettes/2026-09-02.json`](../validate/cassettes/2026-09-02.json) reproduces this
matrix exactly with no credentials.

## Headline

| resolver \ AWS | allowed | explicitDeny | implicitDeny |
|---|---:|---:|---:|
| allow | 651 | 13 | **0** |
| allow-flagged | 7 | 2 | 4 |
| deny | **0** | 15 | 403 |
| unsupported | 2 | 22 | 29 |

**Zero silent under-reports**, across every draw including the half deliberately built as
near-misses. That cell — the resolver calling something unreachable that AWS would permit —
is the only one that is a bug by definition.

**Every remaining over-report is one documented decision.** All 13 are `explicitDeny` on
`AmazonSecurityLakePermissionsBoundary`, and all 13 are D1b below. The
`allow / implicitDeny` cell is empty: there is no longer any over-report this table does not
account for.

Agreement is 1,069/1,148 (93.1%), up from 89.8% before the D7 fix. The number is not a target
and is not comparable to anything — half the draws are constructed near-misses — but the
direction of travel came from fixing a real gap, not from tuning.

## Intentional, with measured cost

| # | Construct | Behaviour | Direction | Observed cost |
|---|---|---|---|---|
| D1a | `Allow` + `NotAction` | Inverted: all known actions minus the exclusions, recorded as a `notaction_inverted` assumption | Exact | `PowerUserAccess` and `AIDevOpsAgentActionsPolicy` resolve cleanly; no under-reports |
| D1b | `Deny` + `NotAction`, and any `NotResource` | Statement skipped, recorded as `unsupported` | Over-report | **13 over-reports — the entire remainder.** All on `AmazonSecurityLakePermissionsBoundary`, whose six `Deny` statements the resolver refuses to evaluate, so it keeps capabilities AWS explicitly denies |
| D2 | Unmodeled condition operators (`Null`, `StringNotLike`, `*IfExists`, `ForAnyValue:*`, …) | Capability kept, operator in residue, reported *unconstrained but flagged* | Over-report | The `allow-flagged` row: 7 allowed against 6 denied |
| D3 | Conditional `Deny` | Never removes a capability; flags it `deny-conditional` | Over-report | Folded into D1b — `AmazonSecurityLakePermissionsBoundary` uses `StringNotLike` in its Denies |
| D5 | No `ResourceArns` in a simulation | Resolver answers `deny` unless a capability is on `*` | Matches AWS | No divergence observed |
| D6 | Unknown action (absent from the snapshot) | Kept literally, recorded as `unknown_action` | Over-report + flag | Fired for real on `awslabs/mcp`'s documented policy: `iam:GetGroupsForUser` does not exist. See the [case study](../examples/awslabs-iam-mcp-server/README.md) |

## D7 — found by the run, now fixed

**Was:** the resolver took the cross product of a statement's `Action` × `Resource` and
matched ARNs textually, ignoring whether an action can apply to a resource of that type.
`sagemaker:DescribeModel` on an `endpoint/*` ARN, `kms:DescribeKey` on an `alias/*` ARN,
`codestar-connections:GetIndividualAccessToken` on anything but `*`. **~30 of the original 48
over-reports.**

**Now:** `iam/resource_types.py` compares the policy's resource pattern against the ARN
templates of the resource types the action operates on, taken from the Service Authorization
Reference. Incompatible pairs are dropped and the count is recorded per role as a
`resource_type_pruned` assumption.

The contract that makes this safe is three-valued. `can_apply` returns `True`, `False`, or
**`None` when the data cannot decide** — unknown action, or a service whose resource templates
are missing — and the resolver keeps every capability it cannot rule out. Pruning is the only
operation in the resolver that *removes* capabilities, so it is the only one that can create an
under-report; failing open is not politeness, it is the whole design. The live run is the proof
it worked: over-reports fell 48 → 13 and the `deny / allowed` cell stayed empty.

## D8 — a limitation of the harness, not the resolver

A condition or resource that compares against a **policy variable** — `${aws:PrincipalAccount}`,
`${aws:PrincipalTag/TargetRegion}` — cannot be exercised by a draw. AWS substitutes the real
value at evaluation time; a draw can only supply the literal `${...}`, which is guaranteed to
mismatch, so AWS denies and the resolver looks wrong when it is not.

These were 27 phantom over-reports. Draws now skip such capabilities rather than ask a question
whose answer is predetermined. This narrows coverage — those grants go untested — and that is
the honest trade against reporting a divergence that does not exist.

## What the refusals cost

Two draws landed in `unsupported / allowed` — the resolver declined and AWS would have
permitted: `AmazonSageMakerFullAccess: sagemaker:StartInferenceExperiment` and
`DataScientist: sagemaker:ListModels`, both because a `NotResource` statement is refused so
nothing can be positively resolved through it. That is the price of D1b, and it is the price
we chose: two draws of lost precision against never inventing a clean bill of health.

## How to add an entry

1. Find the row in `validate/results/<date>.md`.
2. Reproduce it with a single-statement policy in `tests/iam/`.
3. Decide: bug (fix the resolver, as D7) or intentional (add a row here, cite it from the test).
