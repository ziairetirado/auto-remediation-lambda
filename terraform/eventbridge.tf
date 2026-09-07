# -----------------------------------------------------------------------------
# EventBridge rule: fires on every new/updated Security Hub finding that is
# ACTIVE and at CRITICAL/HIGH/MEDIUM severity (configurable). This is what
# gives the pipeline "zero human intervention" - Security Hub -> EventBridge
# -> Lambda, with no queue, approval step, or manual trigger in between.
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "security_hub_findings" {
  name        = "${var.project_name}-securityhub-findings"
  description = "Routes new/updated Security Hub findings to the auto-remediation Lambda"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        RecordState = ["ACTIVE"]
        Workflow = {
          Status = ["NEW"]
        }
        Severity = {
          Label = var.severity_filter
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "invoke_lambda" {
  rule = aws_cloudwatch_event_rule.security_hub_findings.name
  arn  = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings.arn
}
