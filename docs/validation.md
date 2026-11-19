# Validation record

Implementation and local checks completed November 18, 2026. Public sample data is invented. No real AWS resources were scanned in this session.

## Environment and reproducibility

| Item | Observed |
| --- | --- |
| Platform | Linux |
| Python | CPython 3.12.14 |
| Live SDK | Boto3 1.44.6 / Botocore 1.44.6 |
| Dependency installation | Exact `requirements-dev.txt` dependency set installed in a second fresh virtual environment |
| Test suite | 126 tests, all passed |
| Statement coverage | 575 of 628 statements covered: 92% rounded |
| Rule module coverage | 99% statement coverage |
| Ruff lint | Passed |
| Ruff formatting | Passed |
| Package build/install | Version 1.0.0 wheel built and installed successfully |
| Installed console command | Passing fixture generated valid reports and exited 0 |
| Standard-library-only demo | `python -S -m aws_security_auditor ...` generated the full offline report without SDK/site-package loading |
| Native Windows run | Pending; launcher and PowerShell commands supplied, not executed on Windows |
| Live AWS observations | Pending; no AWS credentials/account were used |
| Hosted GitHub Actions | Pending; workflow included, repository not pushed in this session |

Coverage measures statements executed by the instrumented test process. CLI subprocesses are tested for behavior but are not included in these coverage figures. Coverage is not proof of complete correctness. The committed CI threshold is 85%, below the measured 92%.

## Commands run in the clean environment

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m coverage run --source=aws_security_auditor -m unittest discover -s tests -v
python -m coverage report --fail-under=85
python -m pip install --no-deps .
```

The exact successful unittest output and coverage summary are included in `test_results.txt` and `coverage_results.txt`. Tests use no live credentials and no network AWS requests. Stubbed clients use invented placeholders solely to bypass credential discovery; active Stubbers intercept every API request.

## Offline end-to-end observations

| Fixture | Expected | Observed | Exit |
| --- | --- | --- | ---: |
| pass.json | One passing group, complete | PASS=1, no failures/unknowns | 0 |
| fail.json | One unrestricted TCP 22 group | FAIL=1, complete evaluation | 1 |
| security_groups.json | Pass, fail, missing permissions | PASS=1, FAIL=1, UNKNOWN=1 | 2 |
| demo.json | Seven controls, mixed invented data | PASS=8, FAIL=9, UNKNOWN=7, NOT_APPLICABLE=2 | 2 |
| partial.json | IAM discovery denied | Explicit AccessDenied and incomplete IAM scope | 2 |
| Malformed/missing JSON | Clear input error, no new successful report | Error reported; output not created for the new test folder | 2 |

The full demo includes 19 inventory resources, 2 access-key records, and 26 assessments. These counts describe fixture records, not cloud resources scanned. Each finding was checked to contain evidence, recommendation, risk, and verification. Summary and severity counts were checked against assessments. Public reports use invented account 000000000000 and example resource names.

## Control-level fixture comparisons

| Control | Source/reference | Expected | Observed | Why |
| --- | --- | --- | --- | --- |
| EC2-001 | demo: sg-example-public-ssh | FAIL | FAIL | Explicit 0.0.0.0/0 TCP 22 |
| EC2-001 | demo: sg-example-private-ssh | PASS | PASS | Restricted example source |
| EC2-001 | demo: sg-example-unknown | UNKNOWN | UNKNOWN | IpPermissions absent |
| EC2-002 | demo: i-example-v2 | PASS | PASS | Applied, enabled, tokens required |
| EC2-002 | demo: i-example-v1 | FAIL | FAIL | IMDSv1 allowed by optional tokens |
| EC2-002 | demo: i-example-pending | UNKNOWN | UNKNOWN | Metadata update not applied |
| EC2-002 | demo: i-example-terminated | NOT_APPLICABLE | NOT_APPLICABLE | Outside active/restartable baseline |
| EBS-001 | demo: vol-example-encrypted | PASS | PASS | Encrypted=True |
| EBS-001 | demo: vol-example-unencrypted | FAIL | FAIL | False; unattached remains in scope |
| EBS-001 | demo: vol-example-unknown | UNKNOWN | UNKNOWN | Encryption field absent |
| S3-001 | demo: example-audit-account-covered | PASS | PASS | Effective account settings cover bucket gaps |
| S3-001 | demo: example-audit-gap | FAIL | FAIL | Four effective fields False |
| S3-001 | demo: example-audit-unknown | UNKNOWN | UNKNOWN | Account fields unknown and bucket False |
| S3-002 | demo: example-audit-account-covered | PASS | PASS | Versioning enabled |
| S3-002 | demo: example-audit-gap | FAIL | FAIL | Suspended |
| S3-002 | demo: example-audit-unknown | UNKNOWN | UNKNOWN | Versioning read unknown |
| IAM-001 | demo: example-mfa-user / masked key | PASS | PASS | Active key is 89 days old at fixture time |
| IAM-001 | demo: example-review-user / masked key | FAIL | FAIL | Active key is 91 days old |
| IAM-001 | demo: example-unknown | UNKNOWN | UNKNOWN | Key inventory missing |
| IAM-002 | demo: example-mfa-user | PASS | PASS | Registered MFA device present |
| IAM-002 | demo: example-review-user | FAIL | FAIL | Console profile, complete empty device list |
| IAM-002 | demo: example-unknown | UNKNOWN | UNKNOWN | Login profile not established |

## Boundary and collection tests

Tests cover IPv6 RDP, numeric TCP protocol, all protocols, port intervals, UDP exclusion, multiple matches, malformed ports/CIDRs, missing versus empty permissions, stopped/terminated instances, invalid Booleans, and no-attachment volumes.

S3 tests exercise independent account/bucket field combination, True covering unknown, False plus unknown, denied versus absent block configuration, generic 404 versus the exact absent error code, enabled/suspended/never-enabled versioning, paginated bucket discovery, outside-region skips, and legacy region values. AWS documents a null GetBucketLocation result for us-east-1, although Stubber's string model rejects None, so that specific documented result uses a method mock.

IAM tests cover 89 days, exactly 90 days, 90 days plus one second and one microsecond, 91 days, inactive/expired status, timezone offsets, future/naive/missing dates, configurable thresholds, key-ID masking and separation, no-key inventories, registered MFA, denied/incomplete MFA inventory, fresh no-profile identity checks, and a deleted/recreated user race.

Collector tests demonstrate a violation appearing only on a later page; a later-page AccessDenied retaining earlier records; denied discovery versus successful empty inventory; reservation flattening; IAM global scope collected once across two regions; account mismatch before resource collection; expired credentials; bounded retry configuration; timestamp normalization; and deduplication with conflicting-record errors.

## Meaningful bug and regression evidence

**Trigger:** a group has a valid unrestricted administrative rule and a second malformed permission. A similar S3 case has one proven False effective field and other unknown effective fields.

**Initial wrong outcome:** the rule correctly retained FAIL, but the report inferred overall evaluation completeness only from UNKNOWN counts. With no UNKNOWN assessment, it returned 1 and described the evaluation as complete despite the missing input.

**Observed failing regression:** two report tests were added before the fix. Both failed with `AssertionError: 1 != 2` in a 26-test reporting/CLI run. The affected tests are `test_failed_group_with_missing_rule_keeps_scan_incomplete` and `test_failed_bucket_with_unknown_effective_field_keeps_scan_incomplete`.

**Correction:** compound results now carry input completeness separately from status. Assessments and reports retain the proven FAIL and mark evaluation_complete=False; exit code 2 takes precedence. The report also lists incomplete compound evaluations. Both regression tests pass in the final 126-test suite. The pre-fix failure summary is recorded in `regression_evidence.txt`.

## Live observations to complete in your lab

Do not fill these rows using invented fixtures. Use existing resources, sanitize names, and record absence honestly.

| Control | Actual source/resource | Expected | Observed | Explanation/date |
| --- | --- | --- | --- | --- |
| EC2-001 | Pending | Pending | Pending | No live run yet |
| EC2-002 | Pending | Pending | Pending | No live run yet |
| EBS-001 | Pending | Pending | Pending | No live run yet |
| S3-001 | Pending | Pending | Pending | No live run yet |
| S3-002 | Pending | Pending | Pending | No live run yet |
| IAM-001 | Pending | Pending | Pending | No live run yet |
| IAM-002 | Pending | Pending | Pending | No live run yet |

No verified live remediations or measured manual-review time savings are claimed. Native Windows and hosted CI validation should be added here after they actually run.
