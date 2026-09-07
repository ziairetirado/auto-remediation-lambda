"""
Unit tests for the remediation modules. These mock boto3 directly so they
run with no AWS credentials and no network access - fast, deterministic,
CI-friendly.

Run with:  python -m pytest tests/ -v
"""

import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from remediations import s3_remediation, sg_remediation, iam_remediation  # noqa: E402


def make_finding(resources):
    return {"Id": "test-finding-1", "Resources": resources}


class TestS3Remediation:
    @patch("remediations.s3_remediation.s3")
    def test_enables_block_public_access(self, mock_s3):
        finding = make_finding([{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::my-leaky-bucket"}])

        result = s3_remediation.remediate_public_access_block(finding)

        mock_s3.put_public_access_block.assert_called_once_with(
            Bucket="my-leaky-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        assert "my-leaky-bucket" in result

    def test_raises_when_no_bucket_resource(self):
        finding = make_finding([{"Type": "AwsEc2Instance", "Id": "i-123"}])
        try:
            s3_remediation.remediate_public_access_block(finding)
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestSecurityGroupRemediation:
    @patch("remediations.sg_remediation.ec2")
    def test_revokes_unrestricted_ssh_ingress(self, mock_ec2):
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-0123456789",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }
        finding = make_finding([{
            "Type": "AwsEc2SecurityGroup",
            "Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789",
        }])

        result = sg_remediation.remediate_open_security_group(finding)

        mock_ec2.revoke_security_group_ingress.assert_called_once()
        call_kwargs = mock_ec2.revoke_security_group_ingress.call_args.kwargs
        assert call_kwargs["GroupId"] == "sg-0123456789"
        assert call_kwargs["IpPermissions"][0]["FromPort"] == 22
        assert "sg-0123456789" in result

    @patch("remediations.sg_remediation.ec2")
    def test_leaves_non_sensitive_port_alone(self, mock_ec2):
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-safe",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }
        finding = make_finding([{
            "Type": "AwsEc2SecurityGroup",
            "Id": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-safe",
        }])

        result = sg_remediation.remediate_open_security_group(finding)

        mock_ec2.revoke_security_group_ingress.assert_not_called()
        assert "nothing to revoke" in result


class TestIamRemediation:
    @patch("remediations.iam_remediation.iam")
    def test_deactivates_exposed_key(self, mock_iam):
        finding = make_finding([
            {
                "Type": "AwsIamAccessKey",
                "Id": "AKIAABCDEFGHIJKLMNOP",
                "Details": {"AwsIamAccessKey": {"UserName": "ci-deploy-bot"}},
            }
        ])

        result = iam_remediation.remediate_exposed_access_key(finding)

        mock_iam.update_access_key.assert_called_once_with(
            UserName="ci-deploy-bot",
            AccessKeyId="AKIAABCDEFGHIJKLMNOP",
            Status="Inactive",
        )
        mock_iam.tag_user.assert_called_once()
        assert "ci-deploy-bot" in result
        assert "AKIAABCDEFGHIJKLMNOP" in result
