# Design and engineering decisions

The collector and fixture reader return the same `Scan` and `Inventory` structures. `engine.evaluate` passes individual records to pure functions in `rules.py`. Rule functions never make API requests. The reporter serializes the resulting assessments and inventory coverage separately.

## Why assessment status and completeness are separate

PASS means the observed rule input satisfies a selected baseline. FAIL means evidence proves a baseline violation. UNKNOWN means the available input cannot support a decision. NOT_APPLICABLE means the stated baseline does not apply to that resource.

A failed group can contain one known unrestricted rule and another malformed permission. The unrestricted rule is still a FAIL. The malformed input also makes the evaluation incomplete. Compound rules use `RuleResult`, a `(status, evidence)` pair carrying a separate `complete` value. Assessments expose `evaluation_complete`; inventory collection separately exposes `collection_complete`. The report and exit code retain both facts.

All rule UNKNOWN results are incomplete. A S3 effective setting can be known True if either account or bucket is True even when the other value is unknown. A failed effective setting alongside another unknown effective setting remains FAIL plus incomplete. A denied live API request also marks its inventory incomplete even if another layer establishes a PASS for one rule.

## Inventory and pagination

Each envelope identifies the inventory kind, service, region, time, records, completeness, and errors. Successful discovery of zero resources is complete with zero records. A denied inventory records a scope error without inventing resource IDs. Later-page errors preserve earlier records. Known resources with denied configuration reads retain UNKNOWN assessments as appropriate.

EC2 security groups, reservations, and volumes use SDK paginators. Every reservation's instance list is flattened. S3 ListBuckets uses a paginator with a page size; IAM users, access keys, and MFA devices are paginated. Identical repeated resources are deduplicated by identifier. Conflicting duplicate representations are retained once and reported as incomplete inventory, since the scan is not an atomic snapshot.

S3 ListBuckets runs once. BucketRegion from discovery is preferred. When unavailable, the documented GetBucketLocation fallback normalizes null to us-east-1 and EU to eu-west-1. Location failures make the potentially affected selected scope incomplete. Buckets outside selected regions are listed as skipped. Directory buckets are unsupported; version 1 never calls their discovery API.

IAM runs once globally. After NoSuchEntity from GetLoginProfile, a fresh paginated user listing must contain the same ARN and UserId before no console profile is treated as NOT_APPLICABLE. Comparing UserId also catches a deleted-and-recreated username. Other concurrent changes and IAM eventual consistency remain possible.

## Identity, permissions, and failure handling

Live collection requires a named profile, explicit regions, and a 12-digit expected account. STS account comparison precedes resource inventory. SDK timeouts are bounded and standard retries allow four total attempts. Errors retain service, region, operation, code, and a resource reference; raw AWS exception messages and credential objects are never printed.

Only read APIs are used. Permissions are provisioned separately by an administrator using `audit-policy.json`. Credentials remain in the AWS profile system. Remediation is text, never executable mutation in the scanner. Account and resource details in private reports still require review before publication.

## Normalization and identifiers

UTC-aware timestamps are serialized as ISO 8601 strings. Missing fields, False, and unknown values remain distinct. Invalid resource configuration becomes UNKNOWN where identifiable. Invalid discovery identifiers become scope errors. The offline reader rejects malformed JSON, duplicate object keys, NaN/Infinity, invalid envelopes, missing scope declarations, and duplicate inventory/resource identities.

Stable IDs are the first 128 bits of SHA-256 over the NUL-separated account, region, internal resource key, and check ID. Timestamps are excluded. Each IAM key's internal resource key includes its user ARN and full access-key ID so keys remain distinct. Report display IDs mask the key value; a collision in the displayed last four characters does not collapse findings.

## Reports and exit codes

Findings are derived directly from failed assessments. Only FAIL contributes to High/Medium/Low totals. Inventory resources, access keys, and assessments have separate counts. Stable sorting uses service, region, display resource, check ID, and stable ID. Markdown escapes untrusted text and keeps resource evidence on a single line.

JSON and Markdown are serialized before destination replacement. Each file is replaced individually; a failure between replacements is still an output error, so the two files are not a transactional pair. Use the scan timestamp to identify matching reports. Invalid input does not create a new report, but an older report in a reused output folder can remain: always check command status and timestamp.

Exit 2 takes priority over exit 1 whenever collection or evaluation is incomplete. A fully collected empty selected inventory can return 0, with a clear zero-resource scope; it does not establish account security.

## Intentional boundaries

There is no scheduler, dashboard, remediation execution, infrastructure deployment, multi-account collection, or exception suppression. Add these only after real-account validation. Tests verify this version's decisions, including negative and incomplete cases; they cannot prove the deployed AWS permissions or every API race behaves as expected.
