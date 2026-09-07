"""
Remediation: S3 bucket / account has Block Public Access disabled.

Covers Security Hub controls S3.1 (account-level BPA) and S3.8
(bucket-level BPA). Fix: force all four Block Public Access settings to
True on the affected bucket. This is safe to apply broadly because a
bucket that legitimately needs public objects should use a bucket policy
scoped to specific prefixes, not account/bucket-wide public access.
"""

import boto3

s3 = boto3.client("s3")


def remediate_public_access_block(finding):
    bucket_name = _extract_bucket_name(finding)
    if not bucket_name:
        raise ValueError(f"Could not determine bucket name from finding {finding.get('Id')}")

    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    return f"Enabled full S3 Block Public Access on bucket '{bucket_name}'."


def _extract_bucket_name(finding):
    for resource in finding.get("Resources", []):
        if resource.get("Type") == "AwsS3Bucket":
            resource_id = resource.get("Id", "")
            # Resource Id is an ARN like arn:aws:s3:::my-bucket-name
            return resource_id.split(":::")[-1] if ":::" in resource_id else resource_id
    return None
