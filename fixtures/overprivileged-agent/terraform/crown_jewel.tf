# The punchline. The chain terminates in a read of this secret.
resource "aws_secretsmanager_secret" "crown_jewel" {
  name        = "prod/payments/signing-key"
  description = "Fixture placeholder. Never holds a real value."
}
