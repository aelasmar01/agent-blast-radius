# Validation results

Output of `agent-blast-radius validate`. Each run writes `<date>.md` (the confusion
matrix and the divergence lists) and `<date>.json` (every draw and both verdicts, for
reproduction).

## Running it

```bash
uv pip install -e '.[validate]'
agent-blast-radius validate --fixture fixtures/overprivileged-agent --dry-run   # no credentials
agent-blast-radius validate --fixture fixtures/overprivileged-agent             # live
```

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
