# Validation results

Output of `agent-blast-radius validate`. Each run writes `<date>.md` (the confusion
matrix and the divergence lists) and `<date>.json` (every draw and both verdicts, for
reproduction).

## Running it

Three modes, in increasing order of what they prove:

```bash
# 1. The plan and the API budget. No credentials, no verdicts.
agent-blast-radius validate --fixture fixtures/overprivileged-agent --dry-run

# 2. Offline pre-flight: resolver vs each draw's own expectation. No credentials.
agent-blast-radius validate --fixture fixtures/overprivileged-agent --preflight

# 3. The real thing. Needs iam:SimulateCustomPolicy and nothing else.
uv pip install -e '.[validate]'
agent-blast-radius validate --fixture fixtures/overprivileged-agent \
    --record validate/cassettes/2026-09-01.json
```

**Pre-flight is a lint pass, not validation.** It shares every assumption the resolver
makes about IAM, so it cannot catch a case where the semantics were misunderstood —
precisely the class of bug mode 3 exists to find. Passing it is not evidence of
correctness. It is still worth running: the boundary strata build their expectation in
code that never consults the resolver's answer path (`_mutate_resource` constructs an ARN
no granted pattern matches, `_failing_context` flips a modeled condition,
`_wildcard_siblings` picks actions outside the granted set), so a disagreement there is a
real defect, visible offline and free. It runs on every push in CI.

The allow-expected half is drawn from the resolver's own output; agreement there is
circular by construction and is reported separately and discounted.

Recording a live run with `--record` writes a cassette that `--replay` serves back
exactly, with no credentials. That turns one AWS run into a permanent regression corpus:
every divergence you fix keeps a test proving it stays fixed. A replay that meets an
unrecorded request fails loudly rather than guessing — a silently skipped draw would
quietly shrink the matrix.

The live run needs credentials for an identity that has **`iam:SimulateCustomPolicy`
and nothing else**. It creates no resources and reads none. Use a personal account.

Budget as planned: 49 policies (44 managed + 5 fixture roles), ~1,150 draws, ~250 API
calls, about a minute at the default 5 calls/s. Draws are seeded, so two runs against
the same snapshot ask the same questions.

## Reading the matrix

Rows are the resolver's claim, columns are AWS's verdict.

- **`deny / allowed`** is the silent under-report. It is the only cell that is a bug by
  definition. Every instance is listed below the aggregate table, and each must end up
  either fixed or as a numbered entry in `docs/divergences.md`.
- `allow / *Deny` is over-report: noise, not danger.
- `allow-flagged` and `unsupported` rows are the resolver declining to answer. Their
  spread across columns is the price of the conservative choices in `docs/divergences.md`.

There is no scalar agreement rate. Half the draws are near-miss deny cases by design,
and a percentage would hide the one cell that matters.
