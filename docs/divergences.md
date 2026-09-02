# Divergences from `iam:SimulateCustomPolicy`

Observed, not predicted. Source: the run recorded in
[`validate/results/2026-09-02.md`](../validate/results/2026-09-02.md) — 1,172 stratified
draws over 44 AWS managed policies and the fixture's five roles, 253 API calls against
account 234612058514 on 2026-09-02, dataset commit `8e8e0df0ce50`. The committed cassette
reproduces this matrix exactly with no credentials. Replay it offline from
[`validate/cassettes/2026-09-02.json`](../validate/cassettes/2026-09-02.json).

## Headline

| resolver \ AWS | allowed | explicitDeny | implicitDeny |
|---|---:|---:|---:|
| allow | 626 | 13 | 35 |
| allow-flagged | 5 | 2 | 11 |
| deny | **0** | 15 | 412 |
| unsupported | 3 | 22 | 28 |

**Zero silent under-reports.** The `deny / allowed` cell is the only one that is a bug by
definition — the resolver claiming an action is out of reach when AWS would permit it — and
it is empty across every draw, including the half deliberately weighted toward near-misses.

Exact agreement is 1,053/1,172 (89.8%). The remaining 119 split into 48 over-reports
(noise, the safe direction) and 71 draws where the resolver declined to answer. That
percentage is not the point and is not a target: half the draws are constructed near-misses,
so it is not comparable to anything. The empty cell is the point.

## Confirmed intentional

| # | Construct | Behaviour | Direction | Observed cost |
|---|---|---|---|---|
| D1a | `Allow` + `NotAction` | Inverted: all known actions minus the exclusions, recorded as a `notaction_inverted` assumption | Exact | `PowerUserAccess` and `AIDevOpsAgentActionsPolicy` resolve cleanly; 63 draws, no under-reports |
| D1b | `Deny` + `NotAction`, and any `NotResource` | Statement skipped, recorded as `unsupported` | Over-report | **13 over-reports**, all on `AmazonSecurityLakePermissionsBoundary`: six `Deny` statements the resolver refuses to evaluate, so it keeps capabilities AWS explicitly denies |
| D2 | Unmodeled condition operators (`Null`, `StringNotLike`, `*IfExists`, `ForAnyValue:*`, …) | Capability kept, operator recorded in residue, reported *unconstrained but flagged* | Over-report | The `allow-flagged` row: 5 allowed / 13 denied. Flagging costs 13 draws of precision |
| D3 | Conditional `Deny` | Never removes a capability; flags it `deny-conditional` | Over-report | Folded into D1b's 13 — `AmazonSecurityLakePermissionsBoundary` uses `StringNotLike` in its Denies |
| D5 | No `ResourceArns` in a simulation | Resolver answers `deny` unless a capability is on `*` | Matches AWS | Confirmed: no divergence in this cell |
| D6 | Unknown action (absent from the snapshot) | Kept literally, recorded as `unknown_action` | Over-report + flag | Fired for real on `awslabs/mcp`'s documented policy: `iam:GetGroupsForUser` does not exist. See the [case study](../examples/awslabs-iam-mcp-server/README.md) |

## D7 — a real gap the run found, not intentional

**~30 of the 48 over-reports come from one cause: the resolver ignores whether an action can
apply to a resource of that type.**

Within a statement, the resolver takes the cross product of `Action` × `Resource` and matches
ARNs purely textually. AWS additionally requires the resource to be of a type the action
actually operates on. So for a statement listing many SageMaker actions against many SageMaker
resource ARNs, the resolver reports pairs AWS would never allow:

| draw | resolver | AWS |
|---|---|---|
| `sagemaker:DescribeModel` on `arn:aws:sagemaker:*:*:endpoint/*` | allow | implicitDeny |
| `kms:DescribeKey` on a non-`key/` ARN | allow | implicitDeny |
| `codestar-connections:GetIndividualAccessToken` on a `connection/` ARN | allow | implicitDeny |

`sagemaker:DescribeModel` operates on `model*`; `sagemaker:UpdateEndpoint` on `endpoint*` and
`endpoint-config*`; `kms:DescribeKey` on `key*`. `GetIndividualAccessToken` has no resource
type at all, so it is only ever granted on `*`.

The vendored snapshot **already carries** `resource_types` per action — it is the `"r"` key
written by `scripts/build_action_dataset.py`. The resolver simply never reads it.

**Status: open, and it should be fixed rather than documented away.** The direction is safe —
it over-reports, never under-reports — which is why it did not show up as a bug until AWS was
asked. Fixing it needs the resource-type *ARN templates*, which the current snapshot trims
away, so it means a dataset rebuild alongside the resolver change. Any implementation must
fail open: when the resource type cannot be determined, keep the capability. Pruning on
incomplete data would manufacture exactly the under-reports this table is empty of.

## What the refusals cost

Three draws landed in `unsupported / allowed` — the resolver declined and AWS would have
permitted:

- `AmazonSageMakerFullAccess`: `sagemaker:DescribeAppImageConfig` and
  `sagemaker:DescribePartnerApp` on a mutated ARN (the policy's `NotResource` statement is
  refused, so nothing can be positively resolved for them).
- `DataScientist`: `sagemaker:ListModels`, same cause.

That is the price of D1b, and it is the price we chose: three draws of lost precision against
never inventing a false clean bill of health.

## How to add an entry

1. Find the row in `validate/results/<date>.md`.
2. Reproduce it with a single-statement policy in `tests/iam/`.
3. Decide: bug (fix the resolver) or intentional (add a row here, cite it from the test).
