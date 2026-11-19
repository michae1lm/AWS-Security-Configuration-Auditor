# Python AWS Security Configuration Auditor

Prepared for Michael Morris's security engineering and cloud security portfolio.

Manual configuration reviews are difficult to repeat. This Python CLI applies seven documented controls to EC2, EBS, S3, and IAM configuration and writes evidence, risk, recommendations, and verification steps to JSON and Markdown reports. It runs offline with invented fixtures or collects configuration through a read-only AWS profile.

**Implementation status:** all seven controls, AWS collectors, report generation, tests, and a GitHub Actions workflow are included. Local verification is recorded in [docs/validation.md](docs/validation.md). Live AWS observations, a native Windows run, and a hosted GitHub Actions run remain pending. Sample reports are fixture results, not a live AWS audit.

## Run the demo on Windows

1. Extract this entire folder.
2. Install Python 3.11 or newer if needed. The implementation was tested with Python 3.12.14.
3. Double-click `RUN_DEMO.cmd`, or open PowerShell in this folder and run:

```powershell
py -3 -m aws_security_auditor --fixture fixtures/demo.json --output reports/demo
$LASTEXITCODE
```

Open `reports/demo/report.md` or `reports/demo/report.json`. Offline mode uses only Python's standard library; it needs no AWS account, credentials, or SDK installation.

Expected fixture result: **8 PASS, 9 FAIL, 7 UNKNOWN, 2 NOT_APPLICABLE** across **19 inventory resources, 2 access-key records, and 26 assessments**. These are invented records. The exit code is **2** because the demo deliberately includes incomplete input.

Linux/macOS equivalent:

```bash
python3 -m aws_security_auditor --fixture fixtures/demo.json --output reports/demo
```

| Exit code | Meaning |
| --- | --- |
| 0 | Complete evaluation, no failed controls |
| 1 | Complete evaluation, at least one failed control |
| 2 | Invalid input, output/collection error, UNKNOWN, or incomplete compound evaluation |

A proven failure remains FAIL when other input is incomplete. In that case, the report also records incomplete evaluation and returns 2. A complete empty inventory is different from a denied inventory.

## Controls

| ID | Baseline | Failure severity |
| --- | --- | --- |
| EC2-001 | No explicit IPv4/IPv6 `/0` TCP ingress covering 22 or 3389 | High |
| EC2-002 | Require IMDSv2 when instance metadata is enabled | Medium |
| EBS-001 | EBS volumes report encryption enabled | Medium |
| S3-001 | All four combined account/bucket public access block settings enabled | Medium |
| S3-002 | Bucket versioning enabled for recovery | Low |
| IAM-001 | Active IAM user keys do not exceed the configured age threshold | Medium |
| IAM-002 | IAM console users have a registered MFA device | High |

Exact applicability, required fields, unknown states, and limitations are in [docs/control_catalog.md](docs/control_catalog.md).

## Install and run the complete test suite

PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m coverage run --source=aws_security_auditor -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m coverage report
```

Linux/macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
```

Collector tests use `botocore.stub.Stubber` and mocks. They do not contact AWS. The offline-only tests can also run without SDK dependencies:

```powershell
py -3 -m unittest discover -s tests -p test_rules.py -v
py -3 -m unittest discover -s tests -p test_offline.py -v
py -3 -m unittest discover -s tests -p test_cli_reporting.py -v
```

## Read-only live collection

Follow [docs/aws_setup.md](docs/aws_setup.md). An AWS administrator must configure the audit identity and policy before use. The scanner does not create accounts, attach policies, or modify resources.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
aws configure sso --profile audit-lab
aws sso login --profile audit-lab
aws sts get-caller-identity --profile audit-lab
```

Use the verified account number below:

```powershell
.\.venv\Scripts\python.exe -m aws_security_auditor --mode live --profile audit-lab --regions us-west-2 --expected-account YOUR_12_DIGIT_ACCOUNT --output reports/live
```

Multiple regions:

```powershell
.\.venv\Scripts\python.exe -m aws_security_auditor --mode live --profile audit-lab --regions us-west-2 us-east-1 --expected-account YOUR_12_DIGIT_ACCOUNT --max-key-age-days 90 --output reports/live
```

STS verifies the expected account before any resource inventory. IAM is collected once globally. EC2/EBS run in each selected region. S3 discovers general purpose buckets once, filters by region, and reuses the effective account block configuration. Supported list APIs are paginated. Later-page failures retain earlier data and mark the scope incomplete. Repeated identical resources are deduplicated; conflicting duplicates mark the inventory incomplete.

The source can optionally be installed as a package:

```powershell
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\aws-security-auditor.exe --help
```

Fixtures are supplied in this source folder, not installed as package data. Use an explicit fixture path when running the installed command elsewhere. Install `requirements.txt` for live collection.

## Inputs and outputs

- `fixtures/demo.json`: all seven controls, deliberately mixed results.
- `fixtures/security_groups.json`: original three-record demonstration, EC2-001 only.
- `fixtures/pass.json` / `fail.json`: complete exit-code demonstrations.
- `fixtures/partial.json`: denied IAM discovery with explicit incomplete scope.
- `examples/demo/`: generated report from invented data, safe to inspect or publish.
- `reports/`: local scan reports; excluded from Git.

Use `--now 2026-11-18T12:00:00Z` to set an explicit offline evaluation time. Otherwise, offline key age is evaluated at the fixture's `generated_at`. Live mode always uses the scan time. Fixture timestamps and full envelope rules are described in [docs/fixture_format.md](docs/fixture_format.md).

Reports distinguish inventory resources, access keys, assessments, failures, UNKNOWN results, collection completeness, and evaluation completeness. Access-key identifiers are masked in reports, with their full identifier used only in the stable internal hash input. Live account IDs, bucket names, usernames, and other resource identifiers can remain sensitive: review live reports before publication. Public examples in this package use only invented values.

## Scope and limitations

These are seven project baselines, not a compliance certification. A permissive security group does not establish internet reachability. A public access block gap does not prove an S3 object is public. Versioning is a recovery control. Key age does not establish compromise, and a registered MFA device does not prove session MFA enforcement.

Version 1 covers one commercial AWS account, EC2/EBS in selected regions, general purpose S3 buckets in selected regions, and IAM users globally. Directory buckets, Outposts, access-point authorization, root credentials, SSO authentication policy, temporary role sessions, and automatic remediation are outside scope. Prefix lists, combined CIDR ranges, routing, and network ACLs are not expanded. AWS APIs are not an atomic snapshot.

No exception suppression is implemented. Reports explicitly show an empty approved-exception list; findings are never silently changed to PASS. S3's general server-side encryption behavior is not evaluated by an invented blanket KMS requirement.

## Repository guide

| File or folder | Purpose |
| --- | --- |
| `START_HERE.md` | Short next steps for Michael |
| `aws_security_auditor/models.py` | Inventory, assessment, timestamps, stable identifiers |
| `aws_security_auditor/rules.py` | Pure configuration rules |
| `aws_security_auditor/collectors.py` | Read-only paginated AWS collection |
| `aws_security_auditor/offline.py` | Strict fixture envelope validation |
| `aws_security_auditor/engine.py` | Shared evaluator |
| `aws_security_auditor/reporting.py` | Evidence, coverage, JSON/Markdown, exit codes |
| `tests/` | Rule, collector, CLI, report, and schema tests |
| `docs/audit-policy.json` | Audit policy template; replace the placeholder account |
| `.github/workflows/ci.yml` | Tests, lint, formatting, coverage gate |
| `docs/demo_script.md` | Five-minute demonstration and explanation prompts |
| `docs/validation.md` | Actual local observations and pending validation |
| `docs/resume_bullets.md` | Wording matched to completed capabilities |

See [docs/design.md](docs/design.md) for the design and [docs/references.md](docs/references.md) for the official references reviewed during implementation.
