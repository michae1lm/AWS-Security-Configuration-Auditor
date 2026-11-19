# AWS Security Configuration Auditor

Data source: **OFFLINE**. Invented local fixtures; not a live AWS audit.

Account: 000000000000
Requested regions: us-west-2; IAM global.
Checks: EBS-001, EC2-001, EC2-002, IAM-001, IAM-002, S3-001, S3-002; active-key threshold: 90 days.
Collection complete: **False**; evaluation complete: **False**.
Collected at: 2026-11-18T12:00:00+00:00; evaluated at: 2026-11-18T12:00:00+00:00.

A complete scan means these selected checks evaluated the collected scope. Zero findings or zero resources does not prove the account is secure.

## Summary

| PASS | FAIL | UNKNOWN | NOT APPLICABLE |
| ---: | ---: | ---: | ---: |
| 6 | 7 | 5 | 1 |

Inventory resources: 15; access-key records: 0; assessments: 19.
Inventory resources count groups, instances, volumes, buckets, and users once per scope; access keys are counted separately.

## Collection coverage

| Inventory | Region | Resources | Complete | Errors |
| --- | --- | ---: | --- | ---: |
| volumes | us-west-2 | 3 | True | 0 |
| instances | us-west-2 | 4 | True | 0 |
| security_groups | us-west-2 | 4 | True | 0 |
| users | global | 0 | False | 1 |
| buckets | us-west-2 | 4 | True | 0 |

## Failed findings

### HIGH: 2

#### EC2-001 — sg-example-public-rdp

Region: us-west-2; stable ID: 9e29272c88262686941aaeefeba355ec.

- Evidence: ::/0 permits TCP ports \[3389\].
- Risk: Unrestricted administrative ingress expands exposure; routing and actual reachability are not evaluated.
- Recommendation: Restrict TCP 22/3389 to approved sources, or use a managed administrative access method.
- Verification: Re-read inbound rules and rerun EC2-001; separately evaluate network reachability.

#### EC2-001 — sg-example-public-ssh

Region: us-west-2; stable ID: 46d9ac50082eff8a204ce32a6b760fdc.

- Evidence: 0.0.0.0/0 permits TCP ports \[22\].
- Risk: Unrestricted administrative ingress expands exposure; routing and actual reachability are not evaluated.
- Recommendation: Restrict TCP 22/3389 to approved sources, or use a managed administrative access method.
- Verification: Re-read inbound rules and rerun EC2-001; separately evaluate network reachability.

### MEDIUM: 3

#### EBS-001 — vol-example-unencrypted

Region: us-west-2; stable ID: 991a83a0fb0b705b91ec866515ae37d7.

- Evidence: Encrypted=False; attachments=\[\].
- Risk: The volume reports encryption disabled, reducing at-rest data protection.
- Recommendation: Plan an encrypted snapshot/volume replacement and migrate attachments after backup and validation.
- Verification: Check encryption on the replacement, validate the migration, and rerun EBS-001.

#### EC2-002 — i-example-v1

Region: us-west-2; stable ID: a317cc0dd15b576cb12305b459e2a75b.

- Evidence: Instance state='running'; HttpEndpoint='enabled'; HttpTokens='optional'; configuration state='applied'.
- Risk: Optional tokens allow IMDSv1; this observation does not establish credential theft.
- Recommendation: Test application compatibility, then require IMDSv2, or disable an unused metadata endpoint.
- Verification: Wait for MetadataOptions.State=applied, re-read configuration, and rerun EC2-002.

#### S3-001 — example-audit-gap

Region: us-west-2; stable ID: f46b4cb98439c4485f1ced52e79d401d.

- Evidence: BlockPublicAcls: account=False, bucket=False, effective=False.
- Evidence: IgnorePublicAcls: account=False, bucket=False, effective=False.
- Evidence: BlockPublicPolicy: account=False, bucket=False, effective=False.
- Evidence: RestrictPublicBuckets: account=False, bucket=False, effective=False.
- Risk: A public access block baseline gap is present; this does not establish public access to objects.
- Recommendation: Review required access, then enable the missing account or bucket public access block settings.
- Verification: Re-read account and bucket settings and rerun S3-001; separately review authorization policies.

### LOW: 2

#### S3-002 — example-audit-gap

Region: us-west-2; stable ID: b079cf7a161ddfc82ad8a16cffc44076.

- Evidence: Versioning Status='Suspended'; successful configuration read.
- Risk: Recovery from accidental deletion or overwrite is less protected under this versioning baseline.
- Recommendation: Review recovery and storage requirements, then enable bucket versioning where appropriate.
- Verification: Re-read bucket versioning and rerun S3-002. Consider lifecycle management separately.

#### S3-002 — example-audit-no-history

Region: us-west-2; stable ID: 19c9b007fe4f8f301a903a792f077d4a.

- Evidence: Versioning Status=None; successful configuration read.
- Risk: Recovery from accidental deletion or overwrite is less protected under this versioning baseline.
- Recommendation: Review recovery and storage requirements, then enable bucket versioning where appropriate.
- Verification: Re-read bucket versioning and rerun S3-002. Consider lifecycle management separately.

## UNKNOWN assessments

- EBS-001 vol-example-unknown (us-west-2): Encrypted=None; attachments='unknown'.
- EC2-002 i-example-pending (us-west-2): Instance state='running'; HttpEndpoint='enabled'; HttpTokens='required'; configuration state='pending'.
- EC2-001 sg-example-unknown (us-west-2): IpPermissions is missing or is not a list.
- S3-001 example-audit-unknown (us-west-2): BlockPublicAcls: account=None, bucket=False, effective=None.; IgnorePublicAcls: account=None, bucket=False, effective=None.; BlockPublicPolicy: account=None, bucket=False, effective=None.; RestrictPublicBuckets: account=None, bucket=False, effective=None.
- S3-002 example-audit-unknown (us-west-2): Bucket versioning could not be read.

## Incomplete compound evaluations

None.

## Collection errors

- IAM/global list\_users: AccessDenied; resource=scope.

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
| EBS-001 | us-west-2 | vol-example-encrypted | PASS |
| EBS-001 | us-west-2 | vol-example-unencrypted | FAIL |
| EBS-001 | us-west-2 | vol-example-unknown | UNKNOWN |
| EC2-002 | us-west-2 | i-example-pending | UNKNOWN |
| EC2-002 | us-west-2 | i-example-terminated | NOT_APPLICABLE |
| EC2-002 | us-west-2 | i-example-v1 | FAIL |
| EC2-002 | us-west-2 | i-example-v2 | PASS |
| EC2-001 | us-west-2 | sg-example-private-ssh | PASS |
| EC2-001 | us-west-2 | sg-example-public-rdp | FAIL |
| EC2-001 | us-west-2 | sg-example-public-ssh | FAIL |
| EC2-001 | us-west-2 | sg-example-unknown | UNKNOWN |
| S3-001 | us-west-2 | example-audit-account-covered | PASS |
| S3-002 | us-west-2 | example-audit-account-covered | PASS |
| S3-001 | us-west-2 | example-audit-gap | FAIL |
| S3-002 | us-west-2 | example-audit-gap | FAIL |
| S3-001 | us-west-2 | example-audit-no-history | PASS |
| S3-002 | us-west-2 | example-audit-no-history | FAIL |
| S3-001 | us-west-2 | example-audit-unknown | UNKNOWN |
| S3-002 | us-west-2 | example-audit-unknown | UNKNOWN |
