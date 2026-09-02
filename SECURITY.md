# Security notes

## What this repo contains

A deliberately over-privileged agent deployment, used as a controlled fixture, and a set
of declarative escalation rules describing published AWS privilege-escalation methods.
Both are analysis inputs. Neither is an exploit, and nothing here executes against a live
account.

## Standing rules for this repo

- **No credential values, ever.** Not live ones, not dead ones, not commented out. Public
  repo, secret scanners, real reviewers.
- **Every ARN and account ID in the fixtures is fake.**
- If any fixture is ever applied to a real account: a separate, unambiguously personal
  account, `Principal` constrained to that account ID, a budget alarm, and
  `terraform destroy` at the end of the session. A wildcard principal on an
  over-privileged role is a live takeover vector, and role ARNs get scraped.

## Reporting

This is a personal project with no deployed service. If you find something wrong with the
analysis or the fixtures, open an issue.
