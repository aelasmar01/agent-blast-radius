# Cassettes

Recorded `iam:SimulateCustomPolicy` exchanges from live validation runs.

```bash
agent-blast-radius validate --fixture fixtures/overprivileged-agent \
    --record validate/cassettes/<date>.json      # live, records
agent-blast-radius validate --fixture fixtures/overprivileged-agent \
    --replay validate/cassettes/<date>.json      # offline, no credentials
```

A cassette keys on the exact request (policy documents, actions, resource, context), so a
replay reproduces the matrix byte for byte. An unrecorded request raises rather than
guessing: a silently skipped draw would shrink the matrix without saying so.

Nothing here contains a credential — the recorded requests are policy documents that are
already public, and the responses are `allowed` / `explicitDeny` / `implicitDeny`.
