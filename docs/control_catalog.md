# Control catalog

These seven project baselines are the version 1 specification. Resource identifiers and context are supplied by their inventory envelope. Every assessment contains evidence, recommendation, risk, verification, stable ID, source time, and completeness.

## EC2-001 — Restrict administrative ingress — High

**Input:** GroupId; IpPermissions list; each relevant permission's IpProtocol, FromPort/ToPort for TCP, and source arrays. Ports must be integers in 0..65535 with start <= end. IPv4 and IPv6 CIDRs must parse and match their source family. Missing permission lists differ from explicit empty lists.

**Decision:** TCP (`tcp` or `6`) and all protocols (`-1`) are checked for 22 and 3389. A parsed `/0` source covering an administrative TCP port proves FAIL. With no such source and valid required data, PASS. Missing or malformed required input without a proven violation is UNKNOWN. A proven FAIL with other incomplete input remains FAIL and sets evaluation_complete=False. UDP, ICMP, and other valid non-TCP protocols do not trigger this control.

**Evidence:** unrestricted source, covered port(s), and incomplete-data notes. Multiple matches produce one group assessment with multiple evidence entries.

**Recommendation/verification:** restrict to approved sources or use managed administration; re-read rules and rerun the check. The rule evaluates explicit individual `/0` CIDRs, not combined ranges, prefix-list expansion, route tables, network ACLs, or actual reachability. A PASS is scoped to that explicit baseline.

## EC2-002 — Require IMDSv2 — Medium

**Input:** InstanceId, State.Name, MetadataOptions.State, HttpEndpoint, and HttpTokens when enabled.

**Applicability:** terminated and shutting-down instances are NOT_APPLICABLE. Running, pending, stopping, and stopped instances remain in scope.

**Decision:** missing/unknown state or metadata configuration that is not applied is UNKNOWN. Applied + disabled endpoint passes. Applied + enabled endpoint + required tokens passes; optional tokens fails. Unrecognized values remain UNKNOWN.

**Evidence:** instance state, endpoint, token mode, and metadata application state. Recommend testing compatibility and requiring IMDSv2 or disabling unused metadata. Verify after State becomes applied. Optional tokens allow IMDSv1; this is not evidence of stolen credentials.

## EBS-001 — Volume encryption — Medium

**Input:** VolumeId and an exact Boolean Encrypted. Attachments are included as observed evidence, not an applicability gate.

**Decision:** True passes, False fails, missing or invalid values are UNKNOWN. Attached and unattached volumes are in scope and evaluated once per identifier.

**Recommendation/verification:** plan an encrypted replacement through the EBS snapshot/volume migration process; validate data and attachments before retiring the old volume. Encryption cannot be fixed by toggling an existing unencrypted volume's Boolean in place. This does not audit default encryption for future volumes or encryption key policy.

## S3-001 — Effective public access block — Medium

**Input:** bucket Name, AccountBlock, and BucketBlock. Each read is present with a data object, verified absent, or unknown. The four fields are BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets. Only exact Boolean fields are accepted.

**Normalization:** the exact NoSuchPublicAccessBlockConfiguration error means absent, equivalent to four False settings at that level. AccessDenied, NoSuchBucket, generic HTTP 404, or transport failure is unknown, never absent.

| Account value | Bucket value | Effective value |
| --- | --- | --- |
| True | Any | True |
| Any | True | True |
| False | False | False |
| False | Unknown | Unknown |
| Unknown | False or Unknown | Unknown |

**Decision:** evaluate fields independently. All effective values True passes. Any effective False proves FAIL. Otherwise UNKNOWN. A failure with another unknown effective value retains that evidence and sets evaluation_complete=False. Denied collection remains an inventory error even when a known restrictive layer makes a particular rule decisive.

**Recommendation/verification:** review intended access, enable missing settings at an appropriate layer, re-read both levels, and rerun. General purpose buckets only. Account configuration may include effective inherited organization settings. Policies, ACLs, access points, and object authorization are outside this baseline; a gap is not proof of a public bucket.

## S3-002 — Bucket versioning — Low

**Input:** successful GetBucketVersioning data or an unknown read state.

**Decision:** Enabled passes. Suspended or a successful response without Status fails. Denied/missing read or an invalid Status is UNKNOWN.

**Recommendation/verification:** review recovery needs, enable versioning separately, then re-read and rerun. This is a recovery baseline, not a confidentiality finding. Costs and lifecycle management are separate considerations. No blanket KMS/encryption rule is included.

## IAM-001 — Active key age — Medium

**Input:** user ARN, key ID, key Status, timezone-aware CreateDate, explicit UTC evaluation time, and configurable threshold (default 90 days).

**Applicability:** Active keys only. Inactive and Expired keys are NOT_APPLICABLE. Unknown/missing status is UNKNOWN. A successful empty key inventory produces zero key assessments. Missing, malformed, or partial key inventory additionally produces a user-level UNKNOWN for the unestablished key scope; it does not fabricate a key identifier.

**Decision:** compare the full timedelta, not integer days. Exactly 90 days passes at a 90-day threshold. One second or one microsecond older fails. Invalid, naive, missing, or future creation times are UNKNOWN. Each key has a separate stable ID using the user and private full key identifier. Reports mask key values.

**Recommendation/verification:** review/rotate the key or move consumers to temporary credentials; validate consumers before retiring credentials. Age alone does not prove compromise. Root keys, SSO users, and role sessions are outside scope.

## IAM-002 — Registered MFA for console users — High

**Input:** user ARN/identity, GetLoginProfile observation, MFADevices inventory, MFAComplete, and fresh user existence when a profile is absent.

**Decision:** a valid present login profile establishes console access. At least one valid registered device passes; a complete empty list fails; denied/incomplete empty device listing is UNKNOWN. A valid device found before a later-page error establishes registration but leaves collection incomplete. Invalid device data is UNKNOWN.

NoSuchEntity from the profile call is NOT_APPLICABLE only when a fresh complete user listing contains the same ARN and UserId. Deleted/recreated users or inconsistent discovery produce UNKNOWN plus a race error. AccessDenied remains UNKNOWN.

**Recommendation/verification:** register an appropriate MFA device, re-list devices, and rerun. Authentication enforcement and MFA usage in actual sessions are separate controls. SSO authentication is outside scope.
