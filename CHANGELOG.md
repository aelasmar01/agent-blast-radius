# Changelog

## Unreleased

- **D7 fixed**: the resolver now checks whether an action can apply to a resource of that
  type before reporting the pair, using resource-type ARN templates newly vendored from the
  Service Authorization Reference. Found by the first differential run. `can_apply` is
  three-valued and keeps every capability it cannot rule out, because pruning is the only
  operation that can create an under-report. Over-reports fell 48 → 13 with the under-report
  cell still empty.
- First live differential run against `iam:SimulateCustomPolicy`: 1,148 draws, **0 silent
  under-reports**, all 13 remaining over-reports attributable to one documented refusal.
  Recorded to a cassette that replays the matrix exactly with no credentials.
- Fixed a determinism bug that made seeded draws irreproducible across processes: draws were
  sorted on a non-total key, so ties fell back to hash-randomized frozenset order.
- Draws skip grants whose conditions or resources use policy variables, which a draw cannot
  satisfy (D8).
- Case study against `awslabs/mcp`'s `iam-mcp-server`; demo recording.

## 0.1.0 — 2026-09-01

First release. Everything the project plan called v0.1:

- IAM resolver over a pinned, vendored snapshot of the Service Authorization Reference
  (iam-dataset, not botocore — `iam:PassRole` is not an API operation). Identity and
  attached managed policies, wildcard expansion, field-wise ARN matching, four modeled
  condition operators with residue for the rest, Deny subtraction with subsumption.
- `NotAction`/`NotResource` refused per statement and recorded, never approximated.
- Trust policies first-class; the PassRole chain requires the trust fact to fire.
- Taint propagation over per-tool gating and `returns_external_data`.
- Escalation rule pack: 13 cited rules as bound hyperedges; every substitution
  enumerated, provenance path per firing, depth per principal.
- Parsers: Terraform plan JSON, MCP `tools/list`, Bedrock action groups; annotation
  overlay with validation (every tool annotated; gating never assumed).
- Report schema 1.0.0, terminal rendering from it, no score.
- CI mode with `fail_if` gates and independent exit codes for findings vs incomplete.
- Differential validation harness against `iam:SimulateCustomPolicy`: 44-policy corpus,
  stratified boundary-weighted draws, confusion matrix.
- Fixture: a Bedrock-style agent with six Lambda-backed tools, two gated, whose chain
  cannot be reproduced by resolving any single role.
