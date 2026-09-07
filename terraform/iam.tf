# -----------------------------------------------------------------------------
# Lambda execution role: least privilege, scoped to exactly what each
# remediation module needs. No wildcard "*" resource grants for mutating
# actions - only the read-side calls (Describe/Get) are broad, since they're
# non-destructive and Security Hub findings can reference any resource.
# -----------------------------------------------------------------------------

resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_logging" {
  name = "${var.project_name}-logging"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/${var.project_name}-remediate:*"
    }]
  })
}

resource "aws_iam_role_policy" "lambda_remediation_actions" {
  name = "${var.project_name}-remediation-actions"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 remediation: read + set Block Public Access
      {
        Sid    = "S3BlockPublicAccess"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:PutBucketPublicAccessBlock",
          "s3:GetAccountPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock"
        ]
        Resource = "*"
      },
      # Security group remediation: read SG rules, revoke only ingress
      {
        Sid    = "SecurityGroupRemediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress"
        ]
        Resource = "*"
      },
      # IAM remediation: deactivate keys and tag the affected user only
      {
        Sid    = "IamKeyRemediation"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:TagUser",
          "iam:GetUser"
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      # Audit trail
      {
        Sid    = "AuditTable"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Resource = aws_dynamodb_table.audit_log.arn
      },
      # Human notification
      {
        Sid      = "Notify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.remediation_notifications.arn
      }
    ]
  })
}
