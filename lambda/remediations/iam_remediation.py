"""
Remediation: IAM access key flagged as unused/exposed (Security Hub IAM.3,
or a GuardDuty "exposed credentials" style finding forwarded through
Security Hub).

Fix: immediately deactivate (not delete) the specific access key so it
stops working, and tag the IAM user so a human knows which key was
disabled and why. We deactivate rather than delete so the incident can be
reviewed and the key deleted deliberately afterward - deactivation is the
zero-ambiguity, fully-reversible emergency action.
"""

import boto3
from datetime import datetime, timezone

iam = boto3.client("iam")


def remediate_exposed_access_key(finding):
    user_name, access_key_id = _extract_user_and_key(finding)
    if not user_name or not access_key_id:
        raise ValueError(f"Could not determine IAM user/access key from finding {finding.get('Id')}")

    iam.update_access_key(
        UserName=user_name,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )

    iam.tag_user(
        UserName=user_name,
        Tags=[
            {"Key": "auto-remediation:last-action", "Value": "deactivated-exposed-key"},
            {"Key": "auto-remediation:timestamp", "Value": datetime.now(timezone.utc).isoformat()},
        ],
    )

    return f"Deactivated access key '{access_key_id}' for IAM user '{user_name}'."


def _extract_user_and_key(finding):
    user_name = None
    access_key_id = None

    for resource in finding.get("Resources", []):
        if resource.get("Type") == "AwsIamAccessKey":
            details = resource.get("Details", {}).get("AwsIamAccessKey", {})
            user_name = details.get("UserName") or user_name
            access_key_id = resource.get("Id") or access_key_id
        elif resource.get("Type") == "AwsIamUser":
            resource_id = resource.get("Id", "")
            user_name = resource_id.split("/")[-1] if "/" in resource_id else resource_id

    return user_name, access_key_id
