# Terraform fixture

Produces the same five roles and six Lambda-backed tools as `../agent.yaml`, so the
analyzer can be driven from `terraform show -json` with **nothing deployed** and no
credentials (Tier 0 in the project plan). The provider is configured with mock keys and
`skip_*` flags so `terraform plan` succeeds offline from AWS.

```
make fixture-plan      # regenerates ../plan.json
```

`../plan.json` is checked in as the parser's input, so a fresh clone needs neither
Terraform nor a provider download to run the tests.

Every trust policy carries `aws:SourceAccount = var.account_id`. If this were ever
applied, no role here would be assumable from another account.

## If any part of this is ever applied

- Use a separate, unambiguously personal AWS account. No overlap with employer-adjacent
  credentials, email, or CI.
- Set a $5 budget alarm and `terraform destroy` at the end of the session.
- The secret in `crown_jewel.tf` is a placeholder and never holds a real value.
