# agent-blast-radius

**Static, pre-deployment analysis of what an agentic system can actually do to your AWS account.**

> This agent's four tools look scoped. Three hops of IAM later, a prompt injection is an account takeover.

That sentence is the whole project. Everything in this repo exists to make it provable against a
real fixture, in CI, before deployment — not in production telemetry after the fact.

---

## What it looks like

```
$ agent-blast-radius scan ./fixtures/overprivileged-agent
agent-blast-radius  deployment=overprivileged-agent  account=000000000000
  report schema 1.0.0  dataset 8e8e0df0ce50  rules v1

TOOLS
  reachable    read_support_ticket      role=ticket-reader-role       tainted input: ticket_id
  reachable    query_customer_record    role=customer-lookup-role     output of read_support_ticket re-enters the model context
  reachable    call_internal_api        role=internal-api-role        output of read_support_ticket re-enters the model context
  reachable    deploy_helper            role=agent-execution-role     output of read_support_ticket re-enters the model context
  unreachable  run_maintenance_job      role=agent-execution-role     gated: approval_required
  unreachable  rotate_credentials       role=incident-response-role   gated: approval_required

PRINCIPALS REACHABLE FROM ATTACKER INPUT
  depth 0  agent-execution-role         taint-reachable
  depth 0  customer-lookup-role         taint-reachable
  depth 0  internal-api-role            taint-reachable
  depth 0  ticket-reader-role           taint-reachable
  depth 1  incident-response-role       via 1 escalation hop

ACCOUNT TAKEOVER
  Attach AdministratorAccess to a reachable role  [iam-attachrolepolicy-self, rhino-2018]  depth 2
    iam:AttachRolePolicy on *  <- incident-response-role/break-glass#BreakGlass

ESCALATION CHAINS (1)
  -> incident-response-role  via PassRole into a new Lambda function  [passrole-lambda-createfunction, rhino-2018]  depth 1
       iam:PassRole on arn:aws:iam::000000000000:role/*  <- agent-execution-role/helper-deploy#PassRoleToLambda
       lambda:CreateFunction on *  <- agent-execution-role/helper-deploy#ManageHelpers
       lambda:InvokeFunction on *  <- agent-execution-role/helper-deploy#ManageHelpers
       fact: role_trusts_service(role=incident-response-role, service=lambda.amazonaws.com)

REACHABLE CAPABILITIES (199)
  ... (see the full output in docs/post.md)

UNSUPPORTED (0)
  none — the analysis is complete for the constructs this tool models

Reachability is not exploitability: this is what the tool graph permits if the model
can be induced to make the calls, not a prediction that it will.

FAIL: 9 finding(s) tripped fail_if:
  - 'iam:*' matches 190 actions on * as incident-response-role (depth 1): iam:AcceptDelegationRequest, iam:AddClientIDToOpenIDConnectProvider, iam:AddRoleToInstanceProfile, ...  <- incident-response-role/break-glass#BreakGlass
  - 'iam:*' matches iam:PassRole on arn:aws:iam::000000000000:role/* as agent-execution-role (depth 0): iam:PassRole  <- agent-execution-role/helper-deploy#PassRoleToLambda
  - 'kms:Decrypt' matches kms:Decrypt on * as incident-response-role (depth 1): kms:Decrypt  <- incident-response-role/break-glass#BreakGlass
  - escalation chain passrole-lambda-createfunction -> incident-response-role (depth 1)
  - escalation chain iam-attachrolepolicy-self -> all_actions (depth 2)
  - escalation chain iam-putrolepolicy-self -> all_actions (depth 2)
  - chain passrole-lambda-createfunction -> incident-response-role at depth 1 <= max_chain_depth 2
  - chain iam-attachrolepolicy-self -> all_actions at depth 2 <= max_chain_depth 2
  - chain iam-putrolepolicy-self -> all_actions at depth 2 <= max_chain_depth 2
$ echo $?
1
```

## Threat model

An attacker controls text that reaches the model: a support ticket, a scraped page, a document in a
bucket the agent reads. They cannot call AWS directly. They can only induce the model to call the
tools it already has.

The question this tool answers: **given that starting position, what set of AWS actions becomes
reachable?**

It answers it by:

1. Marking which tool inputs are attacker-influenced (explicit annotation — no inference).
2. Propagating taint through the tools the model can reach, respecting per-tool gating.
3. Resolving the IAM identity *and trust* policies behind those tools into an effective capability set.
4. Applying an escalation rule pack to a fixpoint, so multi-action chains such as
   `iam:PassRole` + `lambda:CreateFunction` surface as single findings with a provenance path.

## Reachability is not exploitability

This tool computes what the tool graph **permits** if the model can be induced to make the calls.
It does not predict whether a given model will. It is a map of unlocked doors, not a prediction of
which door someone walks through. Every finding should be read that way.

## Prior art

This re-implements policy resolution that Cloudsplaining and PMapper already do well. I built it to
understand IAM evaluation from the inside, and extended it with taint propagation from untrusted
model input, which those tools don't model.

| Prior art | What it covers |
|---|---|
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) (Salesforce) | Least-privilege violations, wildcard detection, roles assumable by compute services |
| [PMapper](https://github.com/nccgroup/PMapper) (NCC) | Principal-to-principal privilege escalation graphs |
| [Parliament](https://github.com/duo-labs/parliament) (Duo) | Policy linting |
| Rhino Security Labs | The canonical AWS privilege-escalation method list |
| Obsidian, Grafyn, Entrust | Commercial "agent blast radius" — runtime, SaaS-identity focused |
| AgentWard | Published cross-server MCP escalation chains against `awslabs/mcp` |
| AWS Agent Toolkit | IAM condition keys distinguishing agent actions from human ones |

The open gap is not detection quality. Everything commercial here is **runtime observability**.
Nobody is doing **static, pre-deployment, CI-gating analysis over Terraform plus tool manifests**.
That is the pitch: shift-left for agent permissions — catch the chain in the PR.

---

## Scope

**In scope (v1)**

- IAM identity policy parsing: wildcards, resource ARNs, basic conditions.
- Trust policy parsing. `iam:PassRole` + `lambda:CreateFunction` cannot be resolved without it —
  PassRole only succeeds if the target role's trust policy admits `lambda.amazonaws.com`.
- Explicit `Deny`, evaluated after the allow set is assembled.
- 10–12 Rhino escalation methods as declarative, cited rules.
- Two input formats: MCP server manifest, Bedrock agent action group.
- Taint as explicit config annotation.
- Terminal report plus versioned JSON output.
- CI mode with assertion-based failure.

**Out of scope, deliberately — ordered by impact on *this* threat model**

1. **Resource-based policies** beyond trust policies (S3 bucket, KMS key, Lambda resource policies).
   Highest impact, because cross-account reach lives here.
2. Permission boundaries.
3. SCPs.
4. Session policies.

That ordering is not the conventional one. It follows from the threat model: this tool is about what
untrusted input reaches, and the largest unmodeled reach is cross-account via resource policies.

**Single-account assumption.** Stated in the IR and enforced in the analyzer. Cross-account reach
lives in the gap above.

**Gating is the load-bearing axis.** A survey of real deployments
([docs/q2-shared-roles.md](docs/q2-shared-roles.md)) found that locally-run MCP servers and
framework-on-Lambda agents put every tool behind one credential, while Bedrock action groups and
Lambda-backed tools get per-tool roles — but *every* platform exposes per-tool gating (MCP client
`autoApprove`, Bedrock `requireConfirmation`, AgentCore policy engine). So reachability is computed
over gating first and the role graph second, and a single-role deployment with no gating annotations
is told plainly that taint propagation adds nothing, rather than being handed a re-skinned
Cloudsplaining report.

**`NotAction` / `NotResource` are refused, not approximated.** They invert the set logic and are a
silent under-report risk. The offending statement is skipped and recorded in the report's
`unsupported` section with its policy and statement ID; the scan continues, and CI fails closed on
a non-empty `unsupported` list by default. Failing visibly is defensible; under-reporting silently
is not. The same section carries attached managed policies the vendored snapshot doesn't know and
actions it doesn't recognise.

**Conditions.** `StringEquals`, `StringLike`, `ArnLike`, and `Bool` are modeled and carried on the
capability. Every other operator is recorded as residue and the capability is reported as
*unconstrained but flagged* — the conservative direction. A `Deny` only removes a capability when
it is unconditional and its resource pattern fully subsumes the capability's; a conditional or
partial `Deny` is flagged, never trusted.

**Action dataset.** Wildcards expand against a pinned snapshot of the AWS Service Authorization
Reference (via [iam-dataset](https://github.com/iann0036/iam-dataset)), not botocore. botocore lists
API operations, and IAM actions are not API operations: `iam:PassRole` and `s3:ListBucket` do not
exist there, and expanding `iam:*` from it would silently drop the action the headline finding
depends on. The snapshot commit is in `src/agent_blast_radius/data/VERSION` and printed in every
report.

**No 0–100 score.** It invites "how is that computed" and there is no good answer.

---

## Validation

The resolver is differential-tested against `iam:SimulateCustomPolicy` over a fixed corpus of 44
managed policies chosen for construct diversity plus the fixture's roles. Draws are stratified —
half allow-expected, half deny-expected — and the deny half is weighted toward near-misses (right
action / wrong resource, failing condition, actions just outside a wildcard boundary, explicit
Deny, `NotAction` exclusions) because uniform draws are trivially denied and would inflate the
numbers. The output is a confusion matrix, not an agreement rate; the cell that matters is
*resolver says deny, AWS says allowed*. See [validate/results](validate/results/README.md) and
[docs/divergences.md](docs/divergences.md).

An offline `--preflight` mode checks the resolver against each draw's own expectation with no AWS
account, and runs in CI. It is a lint pass, not validation: it shares the resolver's assumptions and
cannot catch a misread of IAM semantics, so passing it is not evidence of correctness. `--record`
and `--replay` turn one live run into a permanent, credential-free regression corpus.

## Install and run

```bash
uvx agent-blast-radius scan ./fixtures/overprivileged-agent
```

No manual setup, no deployed AWS resources, no credentials. The action dataset and the managed
policy documents are vendored and pinned; a scan never touches the network.

`agent.yaml` describes the deployment either as inline IR or as **sources + annotations**:

```yaml
sources:
  terraform_plan: plan.json                 # roles, trust policies, Lambda -> role links
  mcp_tools: mcp-tools.json                 # tool names + argument schemas
  bedrock_action_groups: [action-group.json]  # functions, requireConfirmation, shared Lambda
annotations:                                # per tool: what no document can say
  read_support_ticket:
    gating: none
    tainted_inputs: [ticket_id]             # validated against the tool's declared arguments
    returns_external_data: true             # its output re-enters the model context
  run_maintenance_job: {}                   # gating declared by Bedrock; still needs an entry
```

Every tool needs an annotation entry. Gating is never assumed to be `none`.

### CI mode

```yaml
fail_if:
  reachable_actions_matching: ["iam:*", "sts:AssumeRole", "kms:Decrypt"]
  escalation_chains_found: true
  max_chain_depth: 2               # fail on any chain reachable in <= 2 hops
  unsupported_statements: true     # default: fail closed when the analysis skipped something
```

| exit | meaning |
|---|---|
| 0 | clean |
| 1 | a findings gate tripped |
| 2 | incomplete: `unsupported` is non-empty |
| 3 | both |
| 4 | input error |

Findings and incompleteness are gated independently and never collapse into one code, so a run
that skipped a `NotAction` statement cannot pass as clean, and a real finding cannot hide behind
an incompleteness failure. The repo's own CI asserts the fixture exits with **exactly 1**.

`--json report.json` writes the versioned report (schema `1.0.0`); the terminal output is rendered
from that same model. There is no score.

## Status

v0.1 feature-complete; the first live validation run is pending. See [docs/roadmap.md](docs/roadmap.md)
for the build order and [agent-blast-radius-analyzer-plan.md](agent-blast-radius-analyzer-plan.md)
for the full project plan.

| Component | State |
|---|---|
| IR (tools, roles, policies, taint, gating) | done |
| IAM resolver (identity + managed + trust, Deny, wildcards, conditions) | done |
| Differential validation vs `iam:SimulateCustomPolicy` | harness done; first live run pending |
| MCP / Bedrock / Terraform parsers + annotation overlay | done |
| Reachability fixpoint + rule pack (13 cited rules, bound hyperedges) | done |
| Reporting (schema 1.0.0) + CI mode with independent exit codes | done |

## License

MIT. See [LICENSE](LICENSE).
