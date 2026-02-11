data "archive_file" "broker_zip" {
  type        = "zip"
  source_file = "${path.module}/services/broker/lambda_function.py"
  output_path = "${path.module}/broker.zip"
}


resource "aws_cloudwatch_log_group" "broker_lg" {
  name              = "/aws/lambda/OktaJitBroker"
  retention_in_days = 14
}

resource "aws_lambda_function" "broker" {
  function_name = "OktaJitBroker"
  role          = aws_iam_role.okta_jit_broker_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.broker_zip.output_path
  source_code_hash = data.archive_file.broker_zip.output_base64sha256

  timeout     = 10
  memory_size = 256

  environment {
    variables = {
      DEFAULT_DURATION   = tostring(var.default_duration)
      DEFAULT_ROLE_GROUP = var.default_role_group
      ROLE_MAP           = jsonencode(local.role_map)
    }
  }

  depends_on = [aws_cloudwatch_log_group.broker_lg]
}
