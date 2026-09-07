# Automated Security Remediation (AWS Lambda)

Zero-human-intervention remediation of AWS Security Hub findings: a finding
comes in, the fix goes out. No ticket, no approval queue, no human in the
loop for the fix itself — a person is only ever notified *after* the fact.

## The Problem

Security Hub (fed by GuardDuty, Config, Inspector, IAM Access Analyzer, etc.)
is very good at *finding* misconfigurations — a public S3 bucket, a security
group open to the world, a leaked IAM key — and very bad at *fixing* them.
In practice, most findings sit in a dashboard until someone has time to
triage them, which for common, low-ambiguity issues can mean hours or days
of unnecessary exposure.

This project closes that gap for a specific, well-scoped class of findings:
ones where the correct fix is unambiguous and safe to apply automatically.

## Architecture

```
Security Hub Finding
        │  (ACTIVE, NEW, severity ≥ MEDIUM)
        ▼
EventBridge Rule  ──────────────►  Lambda (Python 3.12)
                                        │
                    ┌───────────────────┼───────────────────┐
                    ▼                   ▼                   ▼
            S3 remediation      SG remediation       IAM remediation
          (Block Public Access) (revoke open ingress) (deactivate key)
                    │                   │                   │
                    └───────────────────┼───────────────────┘
                                        ▼
                        DynamoDB audit log  +  SNS notification
```

**Trigger → Route → Fix → Record → Notify**, in one Lambda invocation, with
no step that waits on a person.

## Findings Covered

| Security Hub Control | Problem | Automated Fix |
|---|---|---|
| `S3.1` / `S3.8` | S3 bucket/account Block Public Access disabled | Force all 4 BPA settings to `true` |
| `EC2.18` / `EC2.19` | Security group allows unrestricted ingress (`0.0.0.0/0` or `::/0`) on a sensitive port (22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 5601) | Revoke only the specific offending rule — other rules on the same group are untouched |
| `IAM.3` / exposed-credential findings | Access key flagged unused or leaked | Deactivate (not delete) the specific key, tag the user for follow-up |

Anything that doesn't match a registered rule is logged and skipped —
the Lambda never guesses at a fix for a finding type it wasn't built to
handle. Extending coverage is a one-line addition to `REMEDIATION_ROUTES`
in `lambda_function.py` plus a new module under `remediations/`.

## Why These Design Choices

- **Deactivate, don't delete (IAM keys).** The remediation needs to be
  instantly effective *and* fully reversible. Deactivation stops the key
  from working immediately; deletion would be a one-way door taken by an
  automated system with no context on downstream impact.
- **Revoke the specific rule, not the whole security group.** A group
  might have five legitimate rules and one bad one. Automation that
  clears the whole group to "fix" one problem creates a new outage.
- **Idempotent by design.** Findings can re-fire (Security Hub sends
  updates, not just creates). Every remediation is checked against a
  DynamoDB record keyed by Finding ID before running, so a re-delivered
  event never double-executes or errors on an already-fixed resource.
- **Notify after, never gate on before.** SNS publishes a summary of what
  was changed and why, but the fix already happened. A human's role here
  is oversight and audit, not a bottleneck.
- **Least-privilege IAM.** The Lambda's execution role grants only the
  exact mutating actions each remediation needs (`PutBucketPublicAccessBlock`,
  `RevokeSecurityGroupIngress`, `UpdateAccessKey`) — see `terraform/iam.tf`.
  A compromised Lambda can't do anything beyond these three narrow actions.
- **Fail-open on the batch, fail-closed on the finding.** One bad/unexpected
  finding raises and is caught per-finding, logged, and reported via SNS —
  it never takes down processing of the rest of the batch.

## Repo Layout

```
auto-remediation-lambda/
├── lambda/
│   ├── lambda_function.py        # Entry point: routes findings, dedups, audits, notifies
│   ├── remediations/
│   │   ├── s3_remediation.py     # Block Public Access fix
│   │   ├── sg_remediation.py     # Revoke unrestricted ingress
│   │   └── iam_remediation.py    # Deactivate exposed access key
│   ├── tests/
│   │   └── test_remediations.py  # Mocked-boto3 unit tests, no AWS creds needed
│   └── requirements.txt
└── terraform/
    ├── main.tf                   # Lambda, DynamoDB audit table, SNS topic
    ├── iam.tf                    # Least-privilege execution role
    ├── eventbridge.tf            # Security Hub → EventBridge → Lambda wiring
    ├── variables.tf
    └── outputs.tf
```

## Deploying

```bash
cd terraform
terraform init
terraform apply -var="notification_email=you@example.com"
```

This assumes Security Hub is already enabled in the account/region. The
EventBridge rule filters on `RecordState=ACTIVE`, `Workflow.Status=NEW`,
and severity (`CRITICAL`/`HIGH`/`MEDIUM` by default, configurable via
`severity_filter`).

## Testing Without Waiting for a Real Finding

Invoke the Lambda directly with a synthetic finding to see the full
route → fix → audit → notify path:

```bash
aws lambda invoke \
  --function-name auto-remediation-remediate \
  --payload file://sample-events/s3-public-bucket.json \
  out.json
```

Unit tests mock all AWS calls, so they run offline:

```bash
cd lambda
python -m pytest tests/ -v
```

## Extending Coverage

1. Write a new `remediations/<name>_remediation.py` with a single function
   `remediate_x(finding) -> str` that performs the fix and returns a
   human-readable description of what it did.
2. Add the Security Hub control ID (or a GuardDuty finding type substring)
   to `REMEDIATION_ROUTES` in `lambda_function.py`.
3. Add the exact IAM permissions the new fix needs to
   `terraform/iam.tf` — nothing broader.
4. Add a unit test with a mocked boto3 client.

## What This Deliberately Does Not Auto-Remediate

Findings where the "correct" fix depends on business context — e.g. an
open security group that's intentionally public for a load balancer, or
an IAM policy that's overly broad by design for a break-glass role — are
not in `REMEDIATION_ROUTES`. Auto-remediation is only safe for findings
where the fix is unambiguous regardless of intent; everything else stays
a Security Hub finding for a human to triage, exactly as it would without
this pipeline.
