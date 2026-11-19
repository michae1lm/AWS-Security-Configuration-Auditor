# AWS Security Configuration Auditor

Data source: **OFFLINE**. Invented local fixtures; not a live AWS audit.

Account: 000000000000
Requested regions: us-west-2; IAM global.
Checks: EC2-001; active-key threshold: 90 days.
Collection complete: **True**; evaluation complete: **True**.
Collected at: 2026-11-19T02:30:26.843538+00:00; evaluated at: 2026-11-19T02:30:26.843538+00:00.

A complete scan means these selected checks evaluated the collected scope. Zero findings or zero resources does not prove the account is secure.

## Summary

| PASS | FAIL | UNKNOWN | NOT APPLICABLE |
| ---: | ---: | ---: | ---: |
| 0 | 1 | 0 | 0 |

Inventory resources: 1; access-key records: 0; assessments: 1.
Inventory resources count groups, instances, volumes, buckets, and users once per scope; access keys are counted separately.

## Collection coverage

| Inventory | Region | Resources | Complete | Errors |
| --- | --- | ---: | --- | ---: |
| security_groups | us-west-2 | 1 | True | 0 |

## Failed findings

### HIGH: 1

#### EC2-001 — sg-public-ssh

Region: us-west-2; stable ID: 6d3d9b8442d885963f6b9aa31066ab48.

- Evidence: 0.0.0.0/0 permits TCP ports \[22\].
- Risk: Unrestricted administrative ingress expands exposure; routing and actual reachability are not evaluated.
- Recommendation: Restrict TCP 22/3389 to approved sources, or use a managed administrative access method.
- Verification: Re-read inbound rules and rerun EC2-001; separately evaluate network reachability.

### MEDIUM: 0

### LOW: 0

## UNKNOWN assessments

None.


## Incomplete compound evaluations

None.

## Collection errors

None.

## Skipped scope

None.

## Limitations and exceptions

- Seven project baselines, not compliance certification or proof of exploitability.
- One commercial AWS account; EC2/EBS and general purpose S3 buckets in requested regions; IAM once globally.
- Directory buckets, access points, Outposts, root credentials, SSO users, and role sessions are outside scope.
- Ingress checks examine individual explicit /0 rules; no aggregate CIDR, prefix-list expansion, routing, ACL, or reachability analysis.
- S3 public access block is a configuration baseline, not full policy/ACL authorization analysis.
- Registered MFA does not prove session MFA enforcement. APIs are not an atomic snapshot; races can occur.
- Read-only collection; remediation must be reviewed and applied separately.

No approved exceptions are configured. Failed results retain their original status.

## All assessments

| Check | Region | Resource | Status |
| --- | --- | --- | --- |
| EC2-001 | us-west-2 | sg-public-ssh | FAIL |
