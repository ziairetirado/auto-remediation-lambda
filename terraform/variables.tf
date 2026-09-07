variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix used to name all resources"
  type        = string
  default     = "auto-remediation"
}

variable "notification_email" {
  description = "Email address subscribed to the SNS remediation-notification topic"
  type        = string
}

variable "log_level" {
  description = "Lambda log level"
  type        = string
  default     = "INFO"
}

variable "severity_filter" {
  description = "Security Hub finding severities that trigger auto-remediation"
  type        = list(string)
  default     = ["CRITICAL", "HIGH", "MEDIUM"]
}
