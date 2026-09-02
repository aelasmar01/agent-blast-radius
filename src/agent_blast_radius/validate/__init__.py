"""Differential validation of the resolver against ``iam:SimulateCustomPolicy``.

The resolver is only worth trusting if it agrees with AWS's own evaluation engine, and
the interesting question is *where* it disagrees. This package draws stratified test
cases from a fixed corpus of managed policies, asks AWS, and produces a confusion
matrix whose headline cell is **resolver says deny, AWS says allowed** — the silent
under-report. No scalar agreement rate: it would be dominated by trivially-denied draws
and hide exactly that cell.

Nothing here runs at scan time. It needs credentials with ``iam:SimulateCustomPolicy``
and nothing else; no resources are ever created.
"""
