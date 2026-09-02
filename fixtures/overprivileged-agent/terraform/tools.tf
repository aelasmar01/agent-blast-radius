# Lambda-backed tools. The function → role link is what the Terraform parser uses to
# attach each tool to its execution role, read from the plan's configuration references
# (`aws_iam_role.<name>.arn`). Written as explicit resources rather than a for_each so
# those references are statically resolvable. Gating and taint come from ../agent.yaml;
# annotations are never inferred from infrastructure.

locals {
  lambda_defaults = {
    handler  = "handler.main"
    runtime  = "python3.12"
    filename = "${path.module}/stub.zip"
  }
}

resource "aws_lambda_function" "read_support_ticket" {
  function_name = "read_support_ticket"
  role          = aws_iam_role.ticket_reader.arn
  handler       = local.lambda_defaults.handler
  runtime       = local.lambda_defaults.runtime
  filename      = local.lambda_defaults.filename
}

resource "aws_lambda_function" "query_customer_record" {
  function_name = "query_customer_record"
  role          = aws_iam_role.customer_lookup.arn
  handler       = local.lambda_defaults.handler
  runtime       = local.lambda_defaults.runtime
  filename      = local.lambda_defaults.filename
}

resource "aws_lambda_function" "call_internal_api" {
  function_name = "call_internal_api"
  role          = aws_iam_role.internal_api.arn
  handler       = local.lambda_defaults.handler
  runtime       = local.lambda_defaults.runtime
  filename      = local.lambda_defaults.filename
}

resource "aws_lambda_function" "deploy_helper" {
  function_name = "deploy_helper"
  role          = aws_iam_role.agent_execution.arn
  handler       = local.lambda_defaults.handler
  runtime       = local.lambda_defaults.runtime
  filename      = local.lambda_defaults.filename
}

resource "aws_lambda_function" "run_maintenance_job" {
  function_name = "run_maintenance_job"
  role          = aws_iam_role.agent_execution.arn
  handler       = local.lambda_defaults.handler
  runtime       = local.lambda_defaults.runtime
  filename      = local.lambda_defaults.filename
}

resource "aws_lambda_function" "rotate_credentials" {
  function_name = "rotate_credentials"
  role          = aws_iam_role.incident_response.arn
  handler       = local.lambda_defaults.handler
  runtime       = local.lambda_defaults.runtime
  filename      = local.lambda_defaults.filename
}
