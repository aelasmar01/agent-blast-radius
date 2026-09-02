# Five roles. Three scoped tool-backing roles (clean negatives), one unremarkable agent
# execution role (the pivot), one over-privileged role that trusts Lambda (the target).
# Mirrors ../agent.yaml statement for statement.

locals {
  account = var.account_id
  region  = var.region
}

# --- Scoped tool-backing roles -------------------------------------------------------

resource "aws_iam_role" "ticket_reader" {
  name               = "ticket-reader-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "ticket_read" {
  name = "ticket-read"
  role = aws_iam_role.ticket_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadTickets"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::support-tickets/*"]
    }]
  })
}

resource "aws_iam_role" "customer_lookup" {
  name               = "customer-lookup-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "customer_read" {
  name = "customer-read"
  role = aws_iam_role.customer_lookup.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "QueryCustomers"
      Effect   = "Allow"
      Action   = ["dynamodb:Query", "dynamodb:GetItem"]
      Resource = ["arn:aws:dynamodb:${local.region}:${local.account}:table/customers"]
    }]
  })
}

resource "aws_iam_role" "internal_api" {
  name               = "internal-api-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "invoke_internal" {
  name = "invoke-internal"
  role = aws_iam_role.internal_api.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeInternalApi"
      Effect   = "Allow"
      Action   = ["execute-api:Invoke"]
      Resource = ["arn:aws:execute-api:${local.region}:${local.account}:abc123/prod/*"]
    }]
  })
}

# --- The pivot: unremarkable in isolation --------------------------------------------

resource "aws_iam_role" "agent_execution" {
  name               = "agent-execution-role"
  assume_role_policy = data.aws_iam_policy_document.bedrock_trust.json
}

resource "aws_iam_role_policy" "helper_deploy" {
  name = "helper-deploy"
  role = aws_iam_role.agent_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassRoleToLambda"
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = ["arn:aws:iam::${local.account}:role/*"]
      },
      {
        Sid      = "ManageHelpers"
        Effect   = "Allow"
        Action   = ["lambda:CreateFunction", "lambda:InvokeFunction"]
        Resource = ["*"]
      },
      {
        Sid      = "NoDirectSecretAccess"
        Effect   = "Deny"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = ["*"]
      },
    ]
  })
}

# --- The target: assumable by Lambda, holds iam:* ------------------------------------

resource "aws_iam_role" "incident_response" {
  name               = "incident-response-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy" "break_glass" {
  name = "break-glass"
  role = aws_iam_role.incident_response.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "BreakGlass"
      Effect   = "Allow"
      Action   = ["iam:*", "secretsmanager:GetSecretValue", "kms:Decrypt"]
      Resource = ["*"]
    }]
  })
}
