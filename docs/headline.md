# The headline finding

> **This agent's four tools look scoped. Three hops of IAM later, a prompt injection is
> an account takeover.**

Committed before the analyzer, on purpose.

The build order is inverted: the fixture is constructed to produce exactly this finding,
and the tool is built backwards from that output. Every proposed feature is tested
against this sentence. If it does not move the sentence toward being provable, it gets
cut.

The two failure modes this guards against:

- **Chasing every IAM edge case.** Never ships. The documented gap list is what makes the
  omissions read as deliberate.
- **Drifting into a general CSPM.** Becomes commodity.
