# Rule binding semantics

Escalation rules are hyperedges over a capability set, not graph edges: most methods
need several actions at once plus preconditions that live outside identity policies
(trust policies, what a Lambda runs as). This document is the contract the engine
implements and `tests/rules/test_binding.py` pins.

## Terms

- **S** — the current capability set: every `(action, resource, conditions)` triple the
  attacker can exercise. Starts as the union of the resolved capabilities of the
  taint-reachable roles.
- **P** — the current principal set: role names the attacker can act as. Starts as the
  taint-reachable roles.
- **Rule** — `id`, declared `variables`, `requires_actions`, `requires_facts`, `grants`,
  `source`.
- **Variable** — a placeholder bound to one concrete role. `{self}` is implicit and
  ranges over **P**; every declared variable ranges over all roles in the deployment.

## Firing

A **firing** is a pair `(rule, σ)` where σ is a substitution assigning every variable of
the rule to a concrete role such that **every** clause holds under σ:

1. Each `requires_actions` clause holds iff some capability `c ∈ S` satisfies all of:
   - `c.action` equals the clause's action (case-insensitive);
   - if the clause names a `resource`, `c.resource` (a pattern) **matches** σ applied to
     it — for `{target}` that is the bound role's ARN;
   - if the clause names `condition` keys, `c.conditions` **admits** each value (an
     unconstrained key admits everything; `StringEquals`/`StringLike` on the key must
     match).
   A capability with non-empty residue may satisfy a clause, but then the firing is
   marked **flagged** and reported as such.
2. Each `requires_facts` entry holds under σ. Facts are evaluated against the
   deployment, not the capability set:
   - `role_trusts_service: {role, service}` — σ(role)'s trust policy admits the service
     principal.
   - `role_trusts_principal: {role, principal}` — σ(role)'s trust policy names
     σ(principal)'s ARN, its account root, or `*`.
   - `tool_backed_by_role: {role}` — some tool in the deployment executes as σ(role).
   - `attached_policy_matches: {action, role}` — the capability satisfying `action` has a
     resource pattern that matches some managed policy ARN attached to σ(role).

Every clause of a rule is evaluated under the **same** σ. Bindings do not leak between
rules or between firings.

## Enumeration

All substitutions are enumerated. If `iam:PassRole` is granted on `role/*` and three
roles trust `lambda.amazonaws.com`, the PassRole rule produces **three firings** with
three bindings and three provenance chains — one finding per reachable principal, not
one finding per rule.

## Grants

`grants` is evaluated under σ:

- `effective_principal: "{target}"` — σ(target) joins **P**; its resolved capabilities
  join **S**. Each new capability carries a chain: the firing's evidence capabilities
  (with their statement provenance), the rule id and σ, and the target role's own
  statement provenance.
- `all_actions: true` — the attacker has full control of the account. The engine records
  the firing and stops enumerating: everything is reachable, and further chains add
  nothing an interviewer would want to read.

## Idempotence and termination

- `(rule, σ)` fires at most once per run.
- A capability already in **S** is not re-added; a principal already in **P** is not
  re-granted.
- The loop repeats until a full pass adds nothing. **S** and **P** only grow and both are
  finite, so it terminates.

## Depth

A principal's depth is 0 if taint-reachable directly, else `1 + max(depth of the
principals whose capabilities were evidence for the firing that granted it)`. A
capability's depth is its principal's depth. `fail_if.max_chain_depth` compares against
this number.

## What is deliberately not modeled

- IAM users and groups: single-account, role-based deployments only. The Rhino methods
  that target users (`CreateAccessKey`, `CreateLoginProfile`, `AttachUserPolicy`, ...)
  are absent from the rule pack for that reason, not by oversight.
- Resource-based policies other than trust policies (see README gaps).
