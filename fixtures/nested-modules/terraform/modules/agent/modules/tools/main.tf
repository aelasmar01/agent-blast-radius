variable "role_arn" { type = string }
resource "aws_lambda_function" "t" {
  function_name = "nested_tool"
  role          = var.role_arn
  handler       = "h.main"
  runtime       = "python3.12"
  filename      = "${path.module}/stub.zip"
}
