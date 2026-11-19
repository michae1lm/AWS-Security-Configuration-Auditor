# Five-minute project demonstration

Use this after you have run the commands and can explain the results in your own words. The script describes implemented behavior; live validation remains pending until you record your AWS observations.

## 0:00–0:45 — Problem and scope

“I built a Python configuration auditor to make a small set of AWS security reviews repeatable. It checks EC2, EBS, S3, and IAM with seven documented baselines. It collects read-only data, keeps the rules independent of AWS, and produces evidence and incomplete-coverage information.”

Show the control table in README. Explain that a configuration violation is not proof of exploitation. Mention that the current demo uses invented data.

## 0:45–1:30 — Run tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Explain one boundary: a 90-day active key passes at the default threshold, but 90 days plus one second fails. The implementation compares the full duration instead of rounding to days. Point to the corresponding tests in `test_rules.py`.

## 1:30–2:30 — Run offline

```powershell
py -3 -m aws_security_auditor --fixture fixtures/demo.json --output reports/demo
$LASTEXITCODE
```

Open `reports/demo/report.md`. Expected: 8 PASS, 9 FAIL, 7 UNKNOWN, 2 NOT_APPLICABLE; 26 assessments from invented input. Exit 2 is intentional. It means incomplete evaluation, not a crashed demo.

Trace `sg-example-public-ssh` from the fixture to EC2-001 in the report. Show the source `/0`, TCP 22, recommendation, and verification. Explain why `sg-example-private-ssh` passes this baseline and why the group with no IpPermissions is UNKNOWN.

## 2:30–3:30 — Show the design

Open `rules.py`, `collectors.py`, and `engine.py`:

- Collectors handle API pagination and errors.
- Rules take dictionaries and return decisions without network calls.
- The engine attaches stable IDs and context.
- Reporting derives failed findings from assessments and keeps collection coverage visible.

Point to a later-page failure test. Explain that page one is retained, but the scope is incomplete. A denied inventory is never replaced with an apparently successful empty scan.

## 3:30–4:30 — Explain one engineering bug

Use the regression recorded in `validation.md`: a known unrestricted rule and another malformed permission originally left a FAIL but could report the evaluation as complete. The fixed code preserves FAIL and also marks evaluation incomplete. The same distinction applies to S3 when one effective setting is False and another remains unknown.

Show `test_failed_group_with_missing_rule_keeps_scan_incomplete`. Explain why both the violation and the missing coverage matter.

## 4:30–5:00 — Live scope and next step

If you have completed a real lab run, show a sanitized comparison from `validation.md`. Otherwise say: “The AWS collection path is implemented and tested with simulated API responses. Real-account validation is the next step.”

Next improvements: real-account comparisons, then report-to-report change tracking or explicit expiring exceptions. Avoid claiming cloud deployment, remediation, or performance savings that have not occurred.

## Questions you should be ready to answer

1. Why can a PASS assessment have High severity metadata? Severity is the baseline's importance when failed; only failed assessments count in failure totals.
2. Why is UNKNOWN different from FAIL? Missing evidence is not proof of a violation or a pass.
3. Why does account-level S3 True cover bucket False? The effective block combines the most restrictive layer independently for each field.
4. Why does a successful empty versioning response fail? It establishes versioning is not enabled under the selected recovery baseline.
5. Why are IAM users global? Repeating them per region would duplicate users, keys, and findings.
6. Why not fix findings automatically? Read-only permissions and separate remediation make collection behavior and change review clear.
7. What does an ingress PASS prove? Only that the explicit individual `/0` administrative-ingress pattern was absent in valid observed input; not full network safety.
8. What has actually been tested? Read `validation.md`; distinguish fixture tests and API mocks from real cloud observations.
