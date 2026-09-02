# Trust policies. Every Principal is constrained to this account so that even if this
# fixture were applied by mistake, no role here is assumable from outside it.

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    sid     = "LambdaAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

data "aws_iam_policy_document" "bedrock_trust" {
  statement {
    sid     = "BedrockAssume"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}
