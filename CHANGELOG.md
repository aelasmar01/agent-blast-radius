# Changelog

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
