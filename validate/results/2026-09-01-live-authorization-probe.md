# Live authorization probe — 2026-09-01

Not the `iam:SimulateCustomPolicy` differential run (that identity lacks the permission —
see below). This is a smaller but genuinely independent check: make real AWS API calls
with a known policy attached and compare the *authorization outcome* against what the
resolver predicts. AWS's real IAM evaluation is the oracle, not a model of it.

**Account** 234612058514, IAM user `sandbox-agent`, `PowerUserAccess` attached.
**Dataset** `8e8e0df0ce50`. All calls read-only; nothing created, nothing billed.

## Method

Each probe calls a read-only API and classifies the result three ways:

- success → **allowed**
- `AccessDenied` / `UnauthorizedOperation` → **denied**
- any other service error → **allowed**; authorization passed and the *service* refused

That third case is the useful discriminator. `organizations:DescribeOrganization`
returned `AWSOrganizationsNotInUseException`, not `AccessDenied` — proof the request was
authorized, which is exactly what `PowerUserAccess` statement 2 grants.

## Result

| action | resolver | AWS (live) | |
|---|---|---|---|
| `iam:ListRoles` | allow | allowed | OK |
| `iam:ListUsers` | deny | denied | OK |
| `iam:GetAccountSummary` | deny | denied | OK |
| `organizations:DescribeOrganization` | allow | allowed (service error) | OK |
| `s3:ListAllMyBuckets` | allow | allowed | OK |
| `lambda:ListFunctions` | allow | allowed | OK |
| `dynamodb:ListTables` | allow | allowed | OK |
| `ec2:DescribeInstances` | allow | allowed | OK |
| `account:ListRegions` | allow | allowed | OK |
| `iam:SimulateCustomPolicy` | deny | denied | OK |

**10/10.** Encoded as regression tests in `tests/iam/test_resolver.py`.

## What this changed

Before this probe the resolver refused `PowerUserAccess` **entirely** — every action came
back `unsupported`, including `s3:GetObject`, because the only broad grant is a
`NotAction` statement and `NotAction` was refused wholesale. Correct by the letter of the
design, and useless: `PowerUserAccess` is one of the most widely attached managed policies
there is, and the report would have been 100% refusal.

`Allow` + `NotAction` is now **inverted** rather than refused: the granted set is every
known action minus the exclusions. That is exact, because the action universe is finite
and enumerable — unlike ARNs, which is why `NotResource` is still refused. The residual
exposure is snapshot staleness, recorded once per statement as a `notaction_inverted`
assumption rather than flagged on each of the ~21,000 resulting capabilities, since every
wildcard expansion (`iam:*` included) already carries the same exposure.

`Deny` + `NotAction` remains refused. Inverting there on a stale snapshot would *shrink*
the denied set and hand back capabilities AWS actually blocks — a false negative, the one
direction this tool refuses to fail in.

## Why the differential run is still blocked

`PowerUserAccess` grants via `NotAction: ["iam:*", "organizations:*", "account:*"]`, and
`iam:SimulateCustomPolicy` sits inside that exclusion:

```
An error occurred (AccessDenied) when calling the SimulateCustomPolicy operation:
User: arn:aws:iam::234612058514:user/sandbox-agent is not authorized to perform:
iam:SimulateCustomPolicy on resource: * because no identity-based policy allows
the iam:SimulateCustomPolicy action
```

The construct blocking the validation run is the same one the run exists to test. To
unblock, attach this inline policy to the identity:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:SimulateCustomPolicy","Resource":"*"}]}
```

It creates nothing, reads no account state, and is not billed.
