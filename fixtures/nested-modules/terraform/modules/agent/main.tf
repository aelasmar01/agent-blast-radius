resource "aws_iam_role" "exec" {
  name = "nested-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "p" {
  name = "inline"
  role = aws_iam_role.exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "S"
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

module "tools" {
  source   = "./modules/tools"
  role_arn = aws_iam_role.exec.arn
}
