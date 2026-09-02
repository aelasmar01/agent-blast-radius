# Case study: `awslabs/mcp` — `iam-mcp-server`

The analyzer pointed at a real, published MCP server rather than at its own fixture.
Read on the `awslabs/mcp` `main` branch, 2026-09-01.

**This is not a vulnerability report.** Everything here is public, documented, intentional
behaviour. Two of the four findings are documentation defects; one is a least-privilege
observation; one is a limitation of *this* analyzer, not of their server. Their design is
secure-by-default in the way that matters most, and that is stated first.

## What the server does

29 MCP tools over AWS IAM — `create_user`, `attach_user_policy`, `put_role_policy`,
`create_access_key`, and 25 more. All 29 run under **one** credential, resolved from the
ambient boto3 chain. That is the shape the Q2 survey found to be the norm
([docs/q2-shared-roles.md](../../docs/q2-shared-roles.md)), and it is why this project
treats gating rather than the role graph as the load-bearing axis.

## Credit first: the defaults are right

`Context._readonly` defaults to `True`, and `main()` requires an explicit `--allow-write`
to enable any mutation. Seventeen write tools additionally take a `confirmed` parameter and
refuse without it. Secure-by-default, opt-in to danger — the correct direction, and worth
saying plainly before any criticism.

## Finding 1 — `iam:GetGroupsForUser` is not an IAM action

The README's *Required IAM Permissions* policy grants 42 actions. One of them does not
exist:

```
UNSUPPORTED (1)
  unknown_action  mcp-credential/documented-required-permissions#statement[0]: iam:GetGroupsForUser
```

The real action is **`iam:ListGroupsForUser`**. Confirmed against both the AWS Service
Authorization Reference and botocore's own service model — neither has
`GetGroupsForUser`; both have `ListGroupsForUser`.

An IAM policy naming a non-existent action is silently accepted by AWS and grants nothing,
so anyone copying that policy gets a `list_groups`/`get_group` tool that fails at runtime
with `AccessDenied` for a reason the policy appears to have covered. This is exactly what
the analyzer's `unknown_action` path exists to catch, and the reason it refuses to quietly
drop actions it does not recognise.

## Finding 2 — the documented credential is not scoped to the default mode

The README publishes one permission set. It is the same whether you run the server in its
read-only default or with `--allow-write`, and it includes:

`iam:CreateAccessKey` · `iam:AttachUserPolicy` · `iam:AttachRolePolicy` ·
`iam:PutUserPolicy` · `iam:PutRolePolicy` · `iam:CreateUser` · `iam:CreateRole` — all on
`Resource: "*"`.

So an operator who runs the server the safe way still provisions a credential that can take
over the account. Read-only is enforced *in the server process*, not in IAM, so it protects
against the model misbehaving and not against the credential being used by anything else.
The analyzer reports the consequence directly:

```
ACCOUNT TAKEOVER
  Attach AdministratorAccess to a reachable role  [iam-attachrolepolicy-self, rhino-2018]  depth 1
    iam:AttachRolePolicy on *  <- mcp-credential/documented-required-permissions#statement[0]
```

**Suggested fix:** publish two policies — a read-only set for the default mode and the full
set for `--allow-write` — and scope the write actions to a resource path where possible.
Defence in depth costs nothing here, and it is the difference between "the model cannot"
and "the credential cannot".

## Finding 3 — the README documents a flag that no longer exists

The README says to add `--readonly` to enable read-only mode. The current code has no such
flag; it has `--allow-write`, and read-only is the default. Following the README verbatim
produces an argument error.

The drift is in the fail-safe direction — someone who thinks they enabled read-only did in
fact get it — but the inverse reading is the dangerous one: a reader may conclude that
*omitting* `--readonly` leaves writes enabled and go looking for a way to turn them off
that no longer exists. Worth a docs PR.

## Finding 4 — a limitation of this analyzer, not of their server

Under `--allow-write` the analyzer reports 30 reachable tools; under the read-only default,
13 reachable and 17 unreachable. Tool reachability is modeled correctly.

**The capability set is identical in both.** That is wrong in a way worth naming: this tool
computes reachable capabilities per *role*, so once any tool makes a role reachable, every
action that role holds counts as reachable. For a Lambda-backed agent that is right — the
function code can call anything its role permits. For an MCP server it over-reports, because
the server mediates: the exposed tool surface is narrower than the credential, and read-only
mode blocks the write tools while the credential keeps the permissions.

Fixing it means per-tool action attribution — mapping each tool to the API calls it actually
makes — which is the natural next extension and is not in v0.1. Until then, treat the
capability set here as *what the credential permits*, not *what the tool surface exposes*.
Finding 2 is unaffected: it is a statement about the credential, which is the thing that
matters if it ever leaves the server process.

## Reproduce

```bash
agent-blast-radius scan examples/awslabs-iam-mcp-server/agent.yaml              # read-only default
agent-blast-radius scan examples/awslabs-iam-mcp-server/agent.allow-write.yaml  # --allow-write
```

`mcp-tools.json` is generated from the server's real `@mcp.tool` functions (names and
argument names read from the AST). `documented-policy.json` is lifted verbatim from the
README's *Required IAM Permissions* block.

## The stated assumption

MCP itself has no attacker-controlled input. The `external_content` tool in these files is
a **stand-in** for any other tool in the same MCP client that returns content someone else
wrote — a ticket reader, a web fetcher, a repo browser. MCP clients load many servers into
one model context, which is the composition AgentWard demonstrated against this same repo.
Without that assumption there is no taint source and nothing here is reachable. It is
declared in the deployment file rather than assumed silently.
