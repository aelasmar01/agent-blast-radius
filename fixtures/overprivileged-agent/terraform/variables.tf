variable "account_id" {
  description = "Account every trust-policy Principal is pinned to. Never a wildcard."
  type        = string
  default     = "000000000000"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}
