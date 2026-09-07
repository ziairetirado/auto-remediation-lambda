terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Package the Lambda source into a zip at plan/apply time.
# ---------------------------------------------------------------------------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/build/lambda.zip"
  excludes    = ["tests", "__pycache__"]
}

# ---------------------------------------------------------------------------
# DynamoDB - immutable audit trail of every remediation attempt.
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "audit_log" {
  name         = "${var.project_name}-audit-log"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "FindingId"

  attribute {
    name = "FindingId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Project = var.project_name
  }
}

# ---------------------------------------------------------------------------
# SNS - notifies humans after the fact. Never blocks the remediation.
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "remediation_notifications" {
  name = "${var.project_name}-notifications"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.remediation_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------------------------------------------------------------------------
# Lambda function
# ---------------------------------------------------------------------------
resource "aws_lambda_function" "remediation" {
  function_name    = "${var.project_name}-remediate"
  description      = "Auto-remediates AWS Security Hub findings with zero human intervention"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN   = aws_sns_topic.remediation_notifications.arn
      AUDIT_TABLE_NAME = aws_dynamodb_table.audit_log.name
      LOG_LEVEL       = var.log_level
    }
  }

  tags = {
    Project = var.project_name
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.remediation.function_name}"
  retention_in_days = 90
}
