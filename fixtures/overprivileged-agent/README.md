# Fixture: overprivileged-agent

A deliberately vulnerable agent deployment, used as the controlled demo and as the
regression target for the analyzer.

`agent.yaml` is the IR-level description — the shape a parser produces from an MCP
manifest or a Bedrock action group. `terraform/` will hold the equivalent
infrastructure-as-code, so the same finding can be produced from
`terraform show -json` output with nothing deployed.

## The finding this fixture exists to produce

> This agent's four tools look scoped. Three hops of IAM later, a prompt injection is an
> account takeover.

## What must stay true

- The chain is **real**, not staged. Each role is individually plausible; the escalation
  comes from their composition.
- `rotate_credentials` is gated, so the report has a clean negative in it. A report where
  everything is red proves nothing.
- Three tool-backing roles are properly scoped, for the same reason.
- Every ARN and account ID here is fake. Nothing in this repo is ever deployed from a
  real credential, and no credential value — live or dead — is ever committed.
