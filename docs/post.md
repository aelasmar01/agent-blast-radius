# What your AI agent can actually do to your AWS account

*Draft. Companion to [agent-blast-radius](https://github.com/aelasmar01/agent-blast-radius).*

Here is an agent. Six tools. Four of them are ungated and, if you read their IAM roles
one at a time, boringly scoped: read a support ticket from one S3 prefix, query one
DynamoDB table, call one internal API, and — the interesting one — create and invoke
short-lived Lambda helpers. That last role holds `iam:PassRole` on `role/*`,
`lambda:CreateFunction`, and `lambda:InvokeFunction`. It also carries an explicit
`Deny` on `secretsmanager:GetSecretValue`, because somebody thought about it.

Elsewhere in the account there is an incident-response role with `iam:*` that trusts
`lambda.amazonaws.com`. The agent's only tool that runs as that role is behind human
approval. Door locked.

Three hops of IAM later, a support ticket is an account takeover.

## The chain

1. `read_support_ticket` takes `ticket_id` and returns customer-authored text. That text
   re-enters the model's context. Every ungated tool is now reachable from whatever the
   customer wrote.
2. `deploy_helper` is ungated. Its role can pass *any* role in the account to Lambda.
3. `incident-response-role` trusts Lambda. `PassRole` + `CreateFunction` + `Invoke`
   and the agent is now that role — `iam:*`, `kms:Decrypt`, and the secret the first
   role was explicitly denied.
4. `iam:AttachRolePolicy` on itself. AdministratorAccess. Done.

The locked door was never the path. The side door was three innocuous-looking grants on
three different roles, none of which is alarming in isolation, plus one trust policy.

## Why a static tool

Everything commercial in the "agent blast radius" space is runtime observability: watch
what the agent does, alert when it does something bad. That is necessary and it is also
late. The chain above is fully determined by three documents that exist before anything
is deployed — the Terraform plan, the tool manifest, and a handful of annotations saying
which inputs an attacker influences and which tools a human gates. It can be caught in
the pull request.

`agent-blast-radius` does that. It resolves the IAM behind each tool into capability
triples `(action, resource, conditions)`, propagates taint through the tool graph
respecting gating, applies a rule pack of published escalation methods as bound
hyperedges, and prints the provenance path for every finding. Then it exits 1.

## The two things people miss

**Second-order taint.** Most threat models stop at "which tool takes user input". But
tool *output* re-enters the model, so a tool that reads attacker-controlled data
promotes the whole agent to tainted. One flag per tool (`returns_external_data`), one
extra fixpoint iteration, and the reachable set goes from one tool to every ungated tool.

**The trust policy is load-bearing.** `iam:PassRole` + `lambda:CreateFunction` is the
canonical escalation and it is unsound to report it from identity policies alone.
PassRole only succeeds if the target role's trust policy admits `lambda.amazonaws.com`.
The tool refuses to fire the rule without that fact, and the fixture's test suite
proves it: strip the trust, the chain disappears. Constrain `iam:PassedToService` to
ECS, the chain disappears. Gate `deploy_helper`, the chain disappears.

## What I did not build, on purpose

This re-implements policy resolution that Cloudsplaining and PMapper already do well.
I built it to understand IAM evaluation from the inside, and extended it with the
taint-propagation layer those tools don't model. A few decisions worth stating out loud:

- **`NotAction` is refused, not approximated.** The statement is skipped, recorded, and
  CI fails closed. Failing visibly beats under-reporting silently.
- **No botocore for action expansion.** botocore lists API operations; IAM actions are
  not API operations. `iam:PassRole` is not in botocore. The tool vendors a pinned
  snapshot of the Service Authorization Reference instead.
- **No score.** A 0–100 number invites "how is that computed" and there is no good answer.
- **Reachability is not exploitability.** This is a map of unlocked doors, not a
  prediction of which one someone walks through.
- **Validated against AWS's own engine**, with a confusion matrix rather than an
  agreement rate, because half the draws are near-miss deny cases by design and a
  percentage would hide the one cell that matters: *we said no, AWS said yes*.

## The number that matters

1,148 stratified draws across 44 AWS managed policies and the fixture's roles, put to
`iam:SimulateCustomPolicy`:

| resolver \ AWS | allowed | explicitDeny | implicitDeny |
|---|---:|---:|---:|
| allow | 651 | 13 | 0 |
| allow-flagged | 7 | 2 | 4 |
| deny | **0** | 15 | 403 |
| unsupported | 2 | 22 | 29 |

The `deny / allowed` cell is empty. That is the resolver claiming an action is out of reach
when AWS would permit it — a false clean bill of health, the only cell that is a bug by
definition — and it stayed empty across every draw, including the half deliberately built as
near-misses: right action with the wrong resource, a condition rigged to fail, actions one
character outside a wildcard boundary.

The thirteen over-reports are all the same refusal: `Deny` combined with `NotResource`, which
the analyzer will not evaluate, so it keeps capabilities AWS denies. That is a decision, it is
written down, and its cost is now measured rather than asserted.

I did not get that on the first run. The first run had 48 over-reports, and chasing them found
a real defect: the analyzer was taking the cross product of a policy's actions and resources
and matching ARNs as text, so it happily reported `sagemaker:DescribeModel` on an `endpoint/*`
ARN — a pair AWS grants nothing for. The fix had to be built so it could only fail in the safe
direction: the compatibility check returns *three* values, and anything it cannot decide keeps
its capability, because pruning is the only operation in the resolver that can invent a false
negative. Then the same harness proved the fix held. That loop closing is the entire argument
for building the harness first.

## What building it turned up

Three things I did not expect, all of which changed the code:

**botocore cannot expand IAM wildcards.** It lists API *operations*, and IAM actions are not API
operations. `iam:PassRole` is not in botocore. Neither is `s3:ListBucket`. Expanding `iam:*` from it
would have silently dropped the exact action the headline finding depends on. The tool vendors a
pinned snapshot of the Service Authorization Reference instead, and `iam:* ⊇ iam:PassRole` is a
permanent regression test.

**Refusing `NotAction` made the tool useless on PowerUserAccess.** Its only broad grant *is* a
`NotAction` statement, so refusing the construct meant refusing every action — `s3:GetObject`
included — on one of the most widely attached policies in AWS. `Allow` + `NotAction` is now
inverted: every known action minus the exclusions, which is exact because the action universe is
finite and enumerable. `Deny` + `NotAction` is still refused, because inverting *that* on a stale
snapshot shrinks the denied set and hands back capabilities AWS actually blocks. Same construct,
opposite decision, for a reason that only shows up if you ask which direction the error falls in.

**Writing the tests found four bugs that would have corrupted the first validation run**, three of
them in code that only executes against real AWS: a resource-policy parameter that was plumbed but
never populated (so trust policies — the load-bearing precondition of the whole PassRole chain —
were never actually tested), a required `CallerArn` that was never sent, a context-key type inferred
from the value's shape rather than the operator, and synthesized statement IDs that IAM rejects
outright, which would have failed every policy in the corpus that lacks explicit ones. The fifth was
found by generating a real Terraform plan instead of hand-writing one: module-relative addresses and
cross-module variable wiring meant the parser broke on essentially every real repository.

None of those are interesting features. They are the difference between a tool that runs and a tool
you can believe.

## The full output

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
  customer-lookup-role: 2 capabilities  (P=0 W=0 R=2 L=0 T=0)  dynamodb:2
  internal-api-role: 1 capabilities  (P=0 W=1 R=0 L=0 T=0)  execute-api:1
  incident-response-role: 192 capabilities  (P=56 W=19 R=38 L=40 T=0)  iam:190, kms:1, secretsmanager:1
      iam:* (190 iam actions) on *  <- incident-response-role/break-glass#BreakGlass
      kms:Decrypt on *  <- incident-response-role/break-glass#BreakGlass
      secretsmanager:GetSecretValue on *  <- incident-response-role/break-glass#BreakGlass
  agent-execution-role: 3 capabilities  (P=1 W=2 R=0 L=0 T=0)  lambda:2, iam:1
      iam:PassRole on arn:aws:iam::000000000000:role/*  <- agent-execution-role/helper-deploy#PassRoleToLambda
  ticket-reader-role: 1 capabilities  (P=0 W=0 R=1 L=0 T=0)  s3:1

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

## Try it

```
uvx agent-blast-radius scan ./fixtures/overprivileged-agent
```

Point it at your own Terraform plan and tool manifest. If it exits 0, that is not a
clean bill of health — read the `unsupported` section and the documented gaps first.
