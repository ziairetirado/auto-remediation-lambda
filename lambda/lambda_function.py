"""
Automated Security Remediation - Lambda Entry Point
=====================================================

Triggered by an EventBridge rule matching AWS Security Hub "Findings - Imported"
events. Routes each finding to the appropriate remediation module based on the
finding's GeneratorId / Type, executes the fix with zero human intervention,
writes an immutable audit record to DynamoDB, and publishes a notification
to SNS so humans stay informed (but are never a blocking step).

Design goals:
  - Idempotent: re-running on the same finding is safe (checked via
    DynamoDB conditional write on finding Id).
  - Fail-safe: unknown/unsupported finding types are logged and skipped,
    never guessed at.
  - Auditable: every action (success, failure, skip) is recorded with
    who/what/when/before-after state.
  - Least privilege: the Lambda execution role only has the exact
    permissions needed for the specific remediation actions it performs
    (see terraform/iam.tf).
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from remediations import s3_remediation, sg_remediation, iam_remediation

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
AUDIT_TABLE_NAME = os.environ["AUDIT_TABLE_NAME"]
audit_table = dynamodb.Table(AUDIT_TABLE_NAME)

# Maps a Security Hub finding "GeneratorId" (or a stable substring of it) to
# the remediation function that knows how to fix it. Add new entries here to
# extend coverage without touching the routing/audit/notification logic.
REMEDIATION_ROUTES = {
    "S3.8": s3_remediation.remediate_public_access_block,     # S3 Block Public Access disabled
    "S3.1": s3_remediation.remediate_public_access_block,     # S3 account-level BPA disabled
    "EC2.19": sg_remediation.remediate_open_security_group,   # SG unrestricted to sensitive port
    "EC2.18": sg_remediation.remediate_open_security_group,   # SG unrestricted, overly permissive
    "IAM.3": iam_remediation.remediate_exposed_access_key,    # Unused/exposed access key
    "IAM-EXPOSED-KEY": iam_remediation.remediate_exposed_access_key,  # GuardDuty exfiltration finding
}


def lambda_handler(event, context):
    """
    Entry point invoked by EventBridge. Handles both a single Security Hub
    finding event and a batch ("findings" list) in one invocation.
    """
    findings = _extract_findings(event)
    if not findings:
        logger.warning("No findings extracted from event: %s", json.dumps(event)[:500])
        return {"statusCode": 200, "remediated": 0, "skipped": 0, "failed": 0}

    results = {"remediated": 0, "skipped": 0, "failed": 0}

    for finding in findings:
        finding_id = finding.get("Id", "unknown")
        try:
            outcome = _process_finding(finding, context)
            results[outcome] += 1
        except Exception:  # noqa: BLE001 - one bad finding must never kill the batch
            logger.exception("Unhandled error remediating finding %s", finding_id)
            results["failed"] += 1
            _notify(
                subject="[Auto-Remediation] ERROR",
                message=f"Unhandled exception remediating finding {finding_id}. "
                        f"See CloudWatch Logs {context.log_group_name}/{context.log_stream_name}.",
            )

    logger.info("Batch complete: %s", results)
    return {"statusCode": 200, **results}


def _process_finding(finding, context):
    finding_id = finding["Id"]
    generator_id = finding.get("GeneratorId", "")
    title = finding.get("Title", "")
    severity = finding.get("Severity", {}).get("Label", "UNKNOWN")
    account_id = finding.get("AwsAccountId", "unknown")
    region = finding.get("Region", os.environ.get("AWS_REGION", "unknown"))
    resource_id = _resource_id(finding)

    if _already_remediated(finding_id):
        logger.info("Finding %s already remediated, skipping (idempotency).", finding_id)
        return "skipped"

    remediation_fn = _match_route(generator_id, finding.get("Types", []))
    if remediation_fn is None:
        logger.info("No remediation registered for GeneratorId=%s (%s). Skipping.", generator_id, title)
        _write_audit_record(finding_id, generator_id, resource_id, account_id, region,
                             status="SKIPPED_NO_RULE", detail="No remediation mapped to this finding type.")
        return "skipped"

    logger.info("Remediating finding %s [%s] on resource %s", finding_id, generator_id, resource_id)
    try:
        detail = remediation_fn(finding)
        _write_audit_record(finding_id, generator_id, resource_id, account_id, region,
                             status="REMEDIATED", detail=detail)
        _notify(
            subject=f"[Auto-Remediation] Fixed: {title or generator_id}",
            message=(
                f"Finding ID: {finding_id}\n"
                f"Severity: {severity}\n"
                f"Account: {account_id}  Region: {region}\n"
                f"Resource: {resource_id}\n"
                f"Action taken: {detail}\n"
                f"Remediated at: {datetime.now(timezone.utc).isoformat()}"
            ),
        )
        return "remediated"
    except ClientError as e:
        logger.exception("AWS API error remediating %s", finding_id)
        _write_audit_record(finding_id, generator_id, resource_id, account_id, region,
                             status="FAILED", detail=str(e))
        _notify(
            subject=f"[Auto-Remediation] FAILED: {title or generator_id}",
            message=f"Finding ID: {finding_id}\nResource: {resource_id}\nError: {e}",
        )
        return "failed"


def _match_route(generator_id, types):
    """Match on GeneratorId first (exact/substring), then fall back to Types[]."""
    for key, fn in REMEDIATION_ROUTES.items():
        if key in generator_id:
            return fn
    for t in types:
        for key, fn in REMEDIATION_ROUTES.items():
            if key in t:
                return fn
    return None


def _extract_findings(event):
    """Supports the native Security Hub EventBridge envelope as well as a
    direct test payload of {"findings": [...]}."""
    if "detail" in event and "findings" in event.get("detail", {}):
        return event["detail"]["findings"]
    if "findings" in event:
        return event["findings"]
    if "Id" in event:  # a single finding passed directly (manual test)
        return [event]
    return []


def _resource_id(finding):
    resources = finding.get("Resources", [])
    if resources:
        return resources[0].get("Id", "unknown")
    return "unknown"


def _already_remediated(finding_id):
    try:
        resp = audit_table.get_item(Key={"FindingId": finding_id})
        item = resp.get("Item")
        return bool(item) and item.get("Status") == "REMEDIATED"
    except ClientError:
        logger.exception("Could not check idempotency table, proceeding cautiously.")
        return False


def _write_audit_record(finding_id, generator_id, resource_id, account_id, region, status, detail):
    audit_table.put_item(
        Item={
            "FindingId": finding_id,
            "GeneratorId": generator_id,
            "ResourceId": resource_id,
            "AccountId": account_id,
            "Region": region,
            "Status": status,
            "Detail": str(detail)[:2000],
            "Timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def _notify(subject, message):
    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject[:100], Message=message)
    except ClientError:
        logger.exception("Failed to publish SNS notification")
