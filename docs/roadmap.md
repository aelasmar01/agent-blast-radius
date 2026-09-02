# Roadmap

**Status (2026-09-02):** W1–W8 complete. v0.1.0 on PyPI; demo recorded; the differential
run against `iam:SimulateCustomPolicy` is done — 1,148 draws, zero silent under-reports,
replayable offline from the committed cassette. It found and closed one real resolver gap
(D7). Nothing on the plan is outstanding.

Deliberately **not** done, so the omissions read as choices: per-tool action attribution
(named in the [case study](../examples/awslabs-iam-mcp-server/README.md)), condition
operators beyond the four modeled, resource-based policies past trust policies, and IAM
users/groups. Each is in the scope table or the divergences doc with a reason.

Hard boundary: 6–8 weekends. Full reasoning lives in
[`agent-blast-radius-analyzer-plan.md`](../agent-blast-radius-analyzer-plan.md).

## Blocking questions — answer both before W1

1. **Does botocore's bundled service model data give clean action expansion, including
   newer services?** ~30 minutes. A bad answer changes data sourcing for the whole
   resolver.
2. **How many IAM roles does a real agent deployment actually use?** The bigger risk. If
   agents commonly run every tool under one shared execution role, taint propagation
   degenerates and the tool reduces to Cloudsplaining with extra YAML. Check three or
   four real deployments (`awslabs/mcp`, Bedrock agent examples). If mostly shared, lead
   with the **gating** dimension rather than the role graph. This is a correctness
   problem, not a positioning one.

## Weekends

| # | Deliverable |
|---|---|
| W1 | Terraform fixture + IR. Commit the headline sentence. |
| W2 | IAM resolver: identity + trust policies, `Deny`, wildcard expansion via botocore, ARN matching, four condition operators. Error on `NotAction`/`NotResource`. |
| W3 | **Validation harness.** Differential-test the resolver against `iam:SimulateCustomPolicy` across the fixture roles and a corpus of AWS managed policies. No deployed resources needed. |
| W4 | MCP manifest and Bedrock action group parsers; taint annotation format. |
| W5 | Reachability fixpoint + rule pack, with a provenance path for every reachable action. |
| W6 | Versioned JSON schema first, terminal rendering from it. |
| W7 | CI mode with assertion-based failure. Tag v0.1. |
| W8 | Write-up, README, demo recording. |

W3 is the centerpiece, not a nice-to-have. "I evaluated my resolver against AWS's own
engine across N policies, here are the four places I intentionally differ" is the single
most legible artifact in the project.

## Cut lines, in order

1. Bedrock parser — ship MCP only.
2. Condition support — flag everything as unconstrained.
3. Second-order taint flag.

**Never cut:** validation harness, provenance paths, trust policy parsing, the prior-art
paragraph in the README.
