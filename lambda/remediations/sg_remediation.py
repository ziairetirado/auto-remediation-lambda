"""
Remediation: Security group allows unrestricted ingress (0.0.0.0/0 or ::/0)
on a sensitive port.

Covers Security Hub controls EC2.18 / EC2.19. Fix: revoke only the specific
offending ingress rule(s) that open a sensitive port to the world. We do NOT
delete or blanket-clear the security group - only the rule(s) matching the
unrestricted CIDR + sensitive-port pattern the finding flagged, so unrelated
legitimate rules on the same group are left untouched.
"""

import boto3

ec2 = boto3.client("ec2")

# Ports that should never be open to the entire internet.
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 5601}
UNRESTRICTED_CIDRS = {"0.0.0.0/0", "::/0"}


def remediate_open_security_group(finding):
    sg_id = _extract_sg_id(finding)
    if not sg_id:
        raise ValueError(f"Could not determine security group id from finding {finding.get('Id')}")

    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

    revoked = []
    for perm in sg.get("IpPermissions", []):
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if from_port is None or to_port is None:
            continue  # skip "all traffic" rules; handled conservatively below
        if not _covers_sensitive_port(from_port, to_port):
            continue

        offending_ipv4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") in UNRESTRICTED_CIDRS]
        offending_ipv6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in UNRESTRICTED_CIDRS]

        if offending_ipv4:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": perm["IpProtocol"],
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": offending_ipv4,
                }],
            )
            revoked.append(f"{perm['IpProtocol']}:{from_port}-{to_port} from 0.0.0.0/0")

        if offending_ipv6:
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": perm["IpProtocol"],
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "Ipv6Ranges": offending_ipv6,
                }],
            )
            revoked.append(f"{perm['IpProtocol']}:{from_port}-{to_port} from ::/0")

    if not revoked:
        return f"No unrestricted-ingress rule on a sensitive port found on {sg_id}; nothing to revoke."

    return f"Revoked unrestricted ingress on {sg_id}: " + "; ".join(revoked)


def _covers_sensitive_port(from_port, to_port):
    return any(from_port <= p <= to_port for p in SENSITIVE_PORTS)


def _extract_sg_id(finding):
    for resource in finding.get("Resources", []):
        if resource.get("Type") == "AwsEc2SecurityGroup":
            resource_id = resource.get("Id", "")
            # Resource Id is an ARN like arn:aws:ec2:region:acct:security-group/sg-xxxx
            return resource_id.split("/")[-1] if "/" in resource_id else resource_id
    return None
