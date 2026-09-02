# Terraform fixture (W1)

Produces the same five roles as `../agent.yaml` so the analyzer can be driven from
`terraform plan -out tfplan && terraform show -json tfplan` with **nothing deployed**
(Tier 0 in the project plan — no AWS account required).

Not yet written.

If any part of this is ever applied:

- Use a separate, unambiguously personal AWS account. No overlap with employer-adjacent
  credentials, email, or CI.
- Constrain every trust-policy `Principal` to your own account ID. A wildcard principal
  on an over-privileged role is a live takeover vector, and role ARNs get scraped.
- Set a $5 budget alarm and `terraform destroy` at the end of the session.
