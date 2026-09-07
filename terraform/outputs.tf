output "lambda_function_name" {
  value = aws_lambda_function.remediation.function_name
}

output "lambda_function_arn" {
  value = aws_lambda_function.remediation.arn
}

output "eventbridge_rule_arn" {
  value = aws_cloudwatch_event_rule.security_hub_findings.arn
}

output "audit_table_name" {
  value = aws_dynamodb_table.audit_log.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.remediation_notifications.arn
}
