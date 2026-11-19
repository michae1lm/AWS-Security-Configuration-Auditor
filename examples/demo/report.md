# AWS Security Configuration Auditor

Data source: **OFFLINE**. Invented local fixtures; not a live AWS audit.

Account: 000000000000
Requested regions: us-west-2; IAM global.
Checks: EBS-001, EC2-001, EC2-002, IAM-001, IAM-002, S3-001, S3-002; active-key threshold: 90 days.
Collection complete: **True**; evaluation complete: **False**.
Collected at: 2026-11-18T12:00:00+00:00; evaluated at: 2026-11-18T12:00:00+00:00.

A complete scan means these selected checks evaluated the collected scope. Zero findings or zero resources does not prove the account is secure.

## Summary

| PASS | FAIL | UNKNOWN | NOT APPLICABLE |
| ---: | ---: | ---: | ---: |
| 8 | 9 | 7 | 2 |

Inventory resources: 19; access-key records: 2; assessments: 26.
Inventory resources count groups, instances, volumes, buckets, and users once per scope; access keys are counted separately.

## Collection coverage

| Inventory | Region | Resources | Complete | Errors |
| --- | --- | ---: | --- | ---: |
| volumes | us-west-2 | 3 | True | 0 |
| instances | us-west-2 | 4 | True | 0 |
| security_groups | us-west-2 | 4 | True | 0 |
| users | global | 4 | True | 0 |
| buckets | us-west-2 | 4 | True | 0 |

## Failed findings

### HIGH: 3

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

#### IAM-002 — arn:aws:iam::000000000000:user/example-review-user

Region: global; stable ID: 010203e3525c2ebafd9a6dcca9961d19.

- Evidence: Console profile present; complete MFA device inventory is empty.
- Risk: A console user has no registered MFA device; session-level MFA use is outside this check.
- Recommendation: Register an appropriate MFA device and separately review authentication enforcement.
- Verification: Re-list the user's registered MFA devices and rerun IAM-002.

### MEDIUM: 4

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

#### IAM-001 — arn:aws:iam::000000000000:user/example-review-user/key/\*\*\*0002

Region: global; stable ID: aac6c439f60af268a399e92c274bc96d.

- Evidence: Active key created=2026-08-19T12:00:00+00:00; age\_seconds=7862400.000000; threshold\_days=90.
- Risk: An active key exceeds the configured review threshold; age alone does not establish compromise.
- Recommendation: Review the active key, migrate consumers to temporary credentials where possible, or rotate and verify consumers.
- Verification: Validate consumer migration, retire the old key separately, and rerun IAM-001.

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
- IAM-001 arn:aws:iam::000000000000:user/example-unknown (global): Access key inventory is missing or malformed.
- IAM-002 arn:aws:iam::000000000000:user/example-unknown (global): Console login profile is unknown.
- S3-001 example-audit-unknown (us-west-2): BlockPublicAcls: account=None, bucket=False, effective=None.; IgnorePublicAcls: account=None, bucket=False, effective=None.; BlockPublicPolicy: account=None, bucket=False, effective=None.; RestrictPublicBuckets: account=None, bucket=False, effective=None.
- S3-002 example-audit-unknown (us-west-2): Bucket versioning could not be read.

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
| IAM-002 | global | arn:aws:iam::000000000000:user/example-api-user | NOT_APPLICABLE |
| IAM-002 | global | arn:aws:iam::000000000000:user/example-mfa-user | PASS |
| IAM-001 | global | arn:aws:iam::000000000000:user/example-mfa-user/key/\*\*\*0001 | PASS |
| IAM-002 | global | arn:aws:iam::000000000000:user/example-review-user | FAIL |
| IAM-001 | global | arn:aws:iam::000000000000:user/example-review-user/key/\*\*\*0002 | FAIL |
| IAM-001 | global | arn:aws:iam::000000000000:user/example-unknown | UNKNOWN |
| IAM-002 | global | arn:aws:iam::000000000000:user/example-unknown | UNKNOWN |
| S3-001 | us-west-2 | example-audit-account-covered | PASS |
| S3-002 | us-west-2 | example-audit-account-covered | PASS |
| S3-001 | us-west-2 | example-audit-gap | FAIL |
| S3-002 | us-west-2 | example-audit-gap | FAIL |
| S3-001 | us-west-2 | example-audit-no-history | PASS |
| S3-002 | us-west-2 | example-audit-no-history | FAIL |
| S3-001 | us-west-2 | example-audit-unknown | UNKNOWN |
| S3-002 | us-west-2 | example-audit-unknown | UNKNOWN |
