output "api_invoke_url" {
  value = aws_apigatewayv2_api.http_api.api_endpoint
}

output "broker_lambda_name" {
  value = aws_lambda_function.broker.function_name
}

output "broker_role_arn" {
  value = aws_iam_role.okta_jit_broker_role.arn
}

output "jit_readonly_role_arn" {
  value = aws_iam_role.jit_prod_readonly.arn
}

output "jit_admin_role_arn" {
  value = aws_iam_role.jit_prod_admin.arn
}
