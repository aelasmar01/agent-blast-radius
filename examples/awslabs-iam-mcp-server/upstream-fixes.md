# Proposed upstream fixes for `awslabs/mcp`

Two documentation defects the analyzer surfaced in `src/iam-mcp-server`, both re-verified
against `main` on 2026-09-02. Neither is a vulnerability; both are small, self-contained
README corrections. Drafted here so the case study and the proposed fix live together.

File them as **two separate PRs** — they are unrelated and reviewers merge small ones faster.

---

## PR 1 — `iam:GetGroupsForUser` is not an IAM action

**Title:** `fix(iam-mcp-server): correct iam:GetGroupsForUser to iam:ListGroupsForUser in README`

**File:** `src/iam-mcp-server/README.md` (~line 105, in *Required IAM Permissions*)

```diff
-                "iam:GetGroupsForUser",
+                "iam:ListGroupsForUser",
```

**Body:**

> The *Required IAM Permissions* policy in the README grants `iam:GetGroupsForUser`, which is
> not an IAM action. The action that backs the `get_group` / `list_groups` tools is
> `iam:ListGroupsForUser`.
>
> Verified against the [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html)
> and botocore's own service model — neither lists `GetGroupsForUser`; both list
> `ListGroupsForUser`.
>
> IAM silently accepts policies that name non-existent actions, and such a statement grants
> nothing. Anyone copying this policy verbatim gets an `AccessDenied` at runtime for a
> permission the policy appears to cover, with no error at policy-creation time to explain it.

---

## PR 2 — the README documents a `--readonly` flag that no longer exists

**Title:** `docs(iam-mcp-server): README describes --readonly; the flag is --allow-write and read-only is the default`

**File:** `src/iam-mcp-server/README.md`, the *Enabling Read-Only Mode* and *MCP Client
Configuration with Read-Only Mode* sections (~lines 223–254).

`main()` in `awslabs/iam_mcp_server/server.py` defines exactly two flags — `--allow-write`
and `--no-confirmation` — and `Context._readonly` defaults to `True`. Passing `--readonly`
as the README instructs produces an argparse error.

Suggested replacement for *Enabling Read-Only Mode*:

~~~markdown
### Read-Only Mode Is the Default

The server starts in read-only mode. All mutating operations are disabled unless you
explicitly opt in with `--allow-write`:

```bash
# Read-only (default) — no flag required
uvx awslabs.iam-mcp-server@latest

# Enable write operations
uvx awslabs.iam-mcp-server@latest --allow-write
```

Write operations additionally require per-call confirmation. `--no-confirmation` disables
that second check and is not recommended.

### MCP Client Configuration

#### Kiro
```json
{
  "mcpServers": {
    "awslabs.iam-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.iam-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "your-aws-profile",
        "AWS_REGION": "us-east-1"
      }
    }
  }
}
```

Add `"--allow-write"` to the args array only if the agent needs to modify IAM.
~~~

**Body:**

> The README's *Read-Only Mode* section instructs users to add a `--readonly` flag. That flag
> is not defined in `main()`; passing it produces an argparse error.
>
> The current behaviour is better than the docs describe: `Context._readonly` defaults to
> `True` and mutations require an explicit `--allow-write`. Secure by default, opt in to
> danger — the README just predates it.
>
> The drift is fail-safe, but the inverse reading is the risk: a reader may conclude that
> *omitting* `--readonly` leaves writes enabled, and go looking for a way to disable them
> that no longer exists.
>
> This PR updates the section to describe the flags the code actually defines, and mentions
> `--no-confirmation` alongside them.

---

## Filing

```bash
gh repo fork awslabs/mcp --clone --remote
cd mcp && git checkout -b fix/iam-mcp-listgroupsforuser
# apply PR 1's one-line change
gh pr create --repo awslabs/mcp --title "..." --body "..."
```

Check `CONTRIBUTING.md` for the commit-message convention and DCO/CLA requirements before
opening either.
