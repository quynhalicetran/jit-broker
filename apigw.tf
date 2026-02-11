resource "aws_apigatewayv2_api" "http_api" {
  name          = "OktaJitBrokerApi"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["*"] # tighten later
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["Authorization", "Content-Type"]
    max_age       = 3600
  }
}

resource "aws_apigatewayv2_authorizer" "okta_jwt" {
  api_id           = aws_apigatewayv2_api.http_api.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "OktaJWT"

  jwt_configuration {
    issuer   = var.okta_issuer
    audience = [var.okta_audience]
  }
}

resource "aws_apigatewayv2_integration" "lambda_integ" {
  api_id           = aws_apigatewayv2_api.http_api.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.broker.invoke_arn
}

resource "aws_apigatewayv2_route" "assume" {
  api_id    = aws_apigatewayv2_api.http_api.id
  route_key = "POST /assume"

  target = "integrations/${aws_apigatewayv2_integration.lambda_integ.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.okta_jwt.id
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "allow_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.broker.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http_api.execution_arn}/*/*"
}
