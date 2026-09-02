# Agent Blast-Radius Analyzer — Project Plan (v2)

**Scope:** 6–8 weekends, hard boundary.
**Primary output:** a shipped CLI tool plus one write-up.
**Goal:** demonstrate depth in IAM evaluation and agent security to hiring managers in cloud security / AI security roles.
**Explicit non-goal:** novelty. This is a deliberate re-implementation with one extension.

---

## 0. Positioning (read this first)

The category is crowded. Before writing code, know what you're standing next to:

| Prior art | What it covers |
|---|---|
| Cloudsplaining (Salesforce) | Least-privilege violations, wildcard detection, roles assumable by compute services |
| PMapper (NCC) | Principal-to-principal privilege escalation graphs |
| Parliament (Duo) | Policy linting |
| Rhino Security Labs | The canonical privilege-escalation method list |
| Obsidian, Grafyn, Entrust | Commercial "agent blast radius" — runtime, SaaS-identity focused |
| AgentWard | Published cross-server MCP escalation chains against `awslabs/mcp` (Mar 2026) |
| AWS Agent Toolkit | IAM condition keys distinguishing agent actions from human ones |

**The IAM half of this project is solved work.** Building it anyway is defensible — you're building it to understand policy evaluation from the inside, which is the resume gap. But that has to be stated, not hidden.

### The narrow gap that is actually open

Everything commercial in this space is **runtime observability**. Nobody is doing **static, pre-deployment, CI-gating analysis over Terraform plus tool manifests**. That's the pitch: shift-left for agent permissions, catch the chain in the PR rather than in production telemetry.

### README requirement

The first screen of the README names the prior art explicitly:

> This re-implements policy resolution that Cloudsplaining and PMapper already do well. I built it to understand IAM evaluation from the inside, and extended it with taint propagation from untrusted model input, which those tools don't model.

A project that names its prior art reads as judgment. The same project without that paragraph reads as someone who didn't check.

---

## 1. What it is

Takes an agentic system's tool definitions and the AWS IAM roles those tools execute under, and computes what an attacker who controls the model's input can reach in the account.

1. Mark which inputs are attacker-influenced.
2. Propagate through the tools the model can call.
3. Resolve the IAM policies behind those tools into an effective action set.
4. Report the subset of AWS actions reachable from untrusted input, including escalation chains such as `iam:PassRole` + `lambda:CreateFunction`.

All the value is in the untrusted-input-to-IAM-action link. Everything else is scaffolding.

---

## 2. Blocking questions — answer both before W1

**Q1. Does botocore's bundled service model data give clean action expansion, including newer services?**
30 minutes. A bad answer changes data sourcing for the whole resolver.

**Q2. How many IAM roles does a real agent deployment actually use?**
This is the bigger risk. If agents commonly run every tool under **one shared execution role**, taint propagation degenerates: every tool is reachable, the effective action set is just that role's policy, and the tool reduces to Cloudsplaining with extra YAML.

Check three or four real deployments — `awslabs/mcp`, Bedrock agent examples, anything visible at work. Count roles per agent.

- Mostly 1:1 or gated → proceed as planned.
- Mostly shared → the core mechanic needs rethinking. The fallback is to lead with the **gating** dimension (which tools sit behind human approval) rather than the role graph.

This is a correctness problem, not a positioning problem. Do not skip it.

---

## 3. Scope boundaries (v1)

**In:**

- IAM identity policy parsing: wildcards, resource ARNs, basic conditions.
- **Trust policy parsing** (see §5).
- Explicit `Deny` handling.
- 10–12 Rhino escalation methods encoded as declarative rules, cited.
- Two input formats: MCP server manifest, Bedrock agent action group.
- Taint marking as explicit config annotation. **No inference.**
- Terminal report plus versioned JSON output. **No web UI.**
- CI mode with assertion-based failure.

**Out, documented as gaps** — ordered by how much each matters for *this* threat model, which deliberately differs from the conventional ordering:

1. **Resource-based policies** beyond trust policies (S3 bucket, KMS key, Lambda resource policies). Highest impact, because cross-account reach lives here.
2. Permission boundaries.
3. SCPs.
4. Session policies.

Explaining the ordering is itself a signal. Put the reasoning in the README.

---

## 4. Distribution is a requirement, not a nicety

The real portfolio gap isn't "no shipped software" — the workbench and Halflife exist. It's **software a stranger installs and runs successfully without you in the room.**

- `uvx agent-blast-radius scan ./fixture` works on a clean machine.
- Tagged release, pinned action dataset, zero manual setup.
- README opens on the threat model, not install instructions.

---

## 5. Correction: trust policies are in scope

`iam:PassRole` + `lambda:CreateFunction` **cannot be resolved from identity policies alone.** PassRole only succeeds if the target role's trust policy allows `lambda.amazonaws.com` to assume it.

Skipping trust policies makes the flagship finding unsound. Cost is low since you're already parsing policy documents. Payoff: the finding upgrades from "these actions are present" to "this specific role is assumable by Lambda and therefore reachable."

---

## 6. Design decisions to fix before implementation

### 6.1 The unit of analysis is a triple, not an action string

`s3:GetObject` on `arn:aws:s3:::public-assets/*` is a different capability from unconstrained `s3:GetObject`. Flatten that and every deployment reports as catastrophic, which makes the tool useless.

Unit = `(action, resource-pattern, condition-residue)` where resource-pattern is a parsed ARN with wildcard semantics and condition-residue marks "constrained by something I didn't model." Set membership, subsumption, and the fixpoint all operate on triples.

### 6.2 Deny, NotAction, NotResource

Explicit `Deny` beats Allow and must be evaluated after the allow set is assembled. Implement properly in v1.

`NotAction` / `NotResource` invert the set logic and are a silent under-report risk. **Refuse to analyze and error out loudly with the statement ID.** Failing visibly is defensible; under-reporting silently is not.

### 6.3 Escalation = hyperedges over a capability set, not graph edges

Most Rhino methods require an AND of several actions plus preconditions. A plain graph traversal can't express that; build one and you rewrite in week 4.

Reachability is a **fixpoint**: start with actions granted to taint-reachable roles, apply every rule whose preconditions hold, add resulting capabilities, repeat until stable. Ten to fifteen lines.

```yaml
- id: passrole-lambda-createfunction
  requires_actions: [iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction]
  requires_facts: [role_trusts_service:lambda.amazonaws.com]
  grants: effective_principal:{passable_role}
  source: rhino-2018
```

The rule pack *format* is the artifact. The count is not.

### 6.4 Gating attribute in the IR

Per-tool taint only has meaning if something breaks the "all tools reachable" default. Include a `gating` field: `none` / `approval_required` / `deterministic`. One field, and it makes propagation real. Pending Q2, this may become the primary axis rather than a secondary one.

### 6.5 Second-order taint — one flag, not a dataflow analysis

Tool output re-enters the model's context, so a tool reading attacker-controlled data creates new tainted input. This is the most interesting AI-security claim in the project and also unbounded if modeled generally.

Model it as `returns_external_data: true` per tool, promoting the agent to tainted if any reachable tool carries it. One extra fixpoint iteration. Call it out in the write-up as the mechanism most people miss.

### 6.6 Language and code shape

Python. botocore's service models decide it; boto3 gives the validation harness for free; `uvx` distribution is clean.

Core = pure functions over frozen dataclasses. Policy documents in, capability triples out. No class hierarchy for statements or evaluators. Easier to test, easier to differential-test, and it sidesteps heavy OOP.

### 6.7 Single-account assumption

State it explicitly in the IR and README. Cross-account reach is out of scope and lives in the resource-based-policy gap.

---

## 7. Build order, inverted

**Write the headline finding before writing the analyzer.**

> *"This agent's four tools look scoped. Three hops of IAM later, a prompt injection is an account takeover."*

Commit it to the repo in W1. Build the Terraform fixture that produces exactly that finding, then build the tool backwards from the output. Every feature that doesn't move that sentence toward being provable gets cut.

---

## 8. Weekend plan

### W1 — Fixture and IR
- Terraform: over-privileged agent deployment, 4–6 tools, roles chained so the finding is real rather than staged.
- Define the IR: tools, roles, policy documents, taint marks, gating.
- Commit the headline sentence.

*Side benefit: this produces the infrastructure-as-code artifact as supporting evidence, without maintaining a commodity Terraform-lab repo separately.*

### W2 — IAM resolver
- Parse identity **and trust** policies. Handle `Deny`. Error on `NotAction`/`NotResource`.
- Expand wildcards via botocore's bundled service models — offline, versioned, no scraping.
- Resource ARN matching against the capability triple.
- Conditions: `StringEquals`, `StringLike`, `ArnLike`, `Bool`. Unrecognized keys are treated as **unconstrained and flagged**. Conservative direction, defensible out loud.

### W3 — Validation harness *(moved up from W7 — this is the centerpiece)*
- Differential-test the resolver against `iam:SimulateCustomPolicy` across the fixture roles and a corpus of AWS managed policies.
- `SimulateCustomPolicy` takes policy JSON as a parameter, so **no deployed resources are required** — just credentials with the simulate permissions.
- Verify how it handles the `ResourcePolicy` parameter, since trust-policy logic is the most likely divergence point.
- Where you diverge: fix it, or document why the divergence is intentional.

*Why this moved: if the goal is demonstrated understanding rather than a novel product, this is the proof. "I evaluated my resolver against AWS's own engine across N policies, here are the four places I intentionally differ" is the single most interview-legible artifact in the project. It was first on the cut list in v1. That was backwards.*

### W4 — Parsers and taint
- MCP manifest → IR. Bedrock action group → IR.
- Taint annotation format. Tool-level in v1, schema shaped so argument-level is additive.

### W5 — Reachability engine
- Fixpoint plus rule pack.
- **Provenance path for every reachable action**: which tool, which role, which policy statement. Provenance is what makes output credible.

### W6 — Reporting
- Design the versioned JSON schema first. Render terminal output from it.

### W7 — CI mode, tag v0.1

```yaml
fail_if:
  reachable_actions_matching: ["iam:*", "sts:AssumeRole", "kms:Decrypt"]
  escalation_chains_found: true
  max_chain_depth: 2
```

Exit non-zero, print the offending provenance path. **No 0–100 score** — it invites "how is that computed" and there's no good answer.

### W8 — Write-up, README, demo
- Post: "What your AI agent can actually do to your AWS account."
- README opening on threat model + prior art (§0).
- asciinema or GIF of the demo run.

---

## 9. Cut lines (revised)

Cut in this order if slipping:

1. **Bedrock parser** — ship MCP only.
2. **Condition support** — flag everything as unconstrained.
3. Second-order taint flag.

**Never cut:** validation harness, provenance paths, trust policy parsing, prior-art paragraph.

---

## 10. Reachability is not exploitability

State this above the fold in the README. The tool computes what the tool graph **permits** if the model can be induced to make the calls, not whether a given model will. It's a map of unlocked doors, not a prediction of which door someone walks through.

Someone will raise it. Raising it first reads as rigor; being caught reads as a gap.

---

## 11. AWS lab requirements

| Tier | Needed? | What |
|---|---|---|
| 0 | **Required** | Nothing deployed. `terraform plan -out` → `terraform show -json`, parse that. Covers W1–W2, W4–W8. |
| 1 | **Required for W3** | An AWS account, an identity with `iam:SimulateCustomPolicy` + `iam:SimulatePrincipalPolicy`, zero deployed resources, ~$0. |
| 2 | Optional, one weekend | Actually detonate the PassRole → CreateFunction chain once, to confirm the encoded rule is true. A few dollars if destroyed same day. |
| 3 | Skip | Running Bedrock agent or live MCP server. Both inputs are static documents you can author by hand. |

### Fixture components (~6 roles)

- **Agent execution role** — `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction`. Unremarkable in isolation.
- **3–4 tool-backing roles** — scoped S3 read, DynamoDB query, internal API. These provide the clean negatives; you need them as much as the positives.
- **One high-privilege role** — trust policy allowing `lambda.amazonaws.com`, holding `iam:*`. The pivot target.
- **A crown-jewel resource** — KMS key or Secrets Manager secret, so the finding terminates with a punchline.
- **One gated tool** — approval flag set, so the report shows something taint does *not* reach. A report where everything is red proves nothing.

### Lab cautions

- Use a **separate AWS account**, unambiguously personal. No overlap with anything employer-adjacent — credentials, email, or CI. You work cyber defense at a bank; deliberately building working escalation chains should have zero connection to that.
- Constrain `Principal` in trust policies to your own account ID. A wildcard principal in an over-privileged fixture is a live takeover vector, and role ARNs get scraped.
- $5 budget alarm. `terraform destroy` at the end of any Tier 2 session.
- Never commit a real credential value, even a dead one. Public repo, secret scanners, reviewers.

---

## 12. Failure modes

- **Chasing every IAM edge case.** Never ships. The gap list in §3 exists so omissions read as deliberate.
- **Drifting into a general CSPM.** Becomes commodity. Test every proposed feature against the headline sentence in §7.
- **Pretending the space is empty.** §0 exists for this. It's the one failure mode that actively hurts rather than merely wastes time.

---

## 13. Deliverables

- Repo, README opening on threat model and prior art.
- Terraform fixture, in-repo.
- Tagged v0.1, installable in one command.
- Validation harness results, published in-repo.
- One write-up with demo output.

The post travels further than the code and is what gets a hiring manager to open the repo.

---

## 14. Optional upside (post-v1)

Point the finished analyzer at **published** MCP servers and Bedrock agent templates and publish what it finds, rather than only at your own fixture.

AgentWard got attention not for being a permission control plane but for aiming itself at a popular AWS repo and filing an issue with real chains in it. Same skills, far better distribution — the tool becomes the instrument and the finding becomes the artifact.

Do this only after v1 ships. It is not a substitute for the fixture, which you still need as a controlled demo.
