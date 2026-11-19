# Connect your own AWS lab

Live collection is implemented and mock-tested. This package does not contain an AWS profile or live-account validation. Do these steps on your own computer; never paste credentials into this project or a chat.

## 1. Prepare a read-only identity

Install AWS CLI version 2 using the official Windows instructions linked in `references.md`. Open a new PowerShell window and run `aws --version`.

If your lab uses IAM Identity Center, have the administrator assign an audit role/permission set with the actions in `audit-policy.json`. Replace the placeholder `000000000000` in the IAM user ARN with your account number before the policy is attached. EC2 discovery and global lists require wildcard resource scope; user configuration reads are limited to users in the selected account. The scanner does not attach this policy itself.

```powershell
aws configure sso --profile audit-lab
aws sso login --profile audit-lab
aws sts get-caller-identity --profile audit-lab
```

Use the start URL or issuer URL and SSO region supplied by the administrator or access portal. That SSO region is distinct from the region whose resources you scan. Successful sign-in alone does not grant every audit action.

For a personal lab without Identity Center, an administrator may instead configure a dedicated IAM audit user with this policy and a programmatic key. Configure it using `aws configure --profile audit-lab` and the CLI's private prompts. Prefer temporary credentials where available. Do not use root credentials for this project.

## 2. Install the SDK

From the extracted project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## 3. Check the account and run one region

Read the Account field from `aws sts get-caller-identity`. Substitute it below; the text `YOUR_12_DIGIT_ACCOUNT` is a placeholder and is intentionally rejected by the CLI.

```powershell
.\.venv\Scripts\python.exe -m aws_security_auditor --mode live --profile audit-lab --regions us-west-2 --expected-account YOUR_12_DIGIT_ACCOUNT --output reports/live
$LASTEXITCODE
```

The scanner verifies the account through STS before inventory. A mismatch stops the run. Empty or denied inventory is reported explicitly; exit code 2 means incomplete collection/evaluation or another error, while 1 means complete evaluation with findings.

`reports/live` is excluded from Git. Live reports may contain real account, user, bucket, instance, and volume identifiers. Never copy them into `examples/` without review and sanitization. Public examples already provided use invented data only.

## 4. Validate real observations

Compare the scanner with the AWS console for resource types you already have. Record expected and observed results in `validation.md`. If a type is absent, record zero resources and use fixtures to demonstrate that rule. You do not need to create public ingress or weaken an IAM user to get a failed example.

For a remediation demonstration, use a genuine issue you understand, make the change separately with an appropriate administrative identity, and rescan. EBS encryption normally requires migration, so describe the process instead of disrupting a working volume for a demo. Enabling S3 versioning changes recovery/storage behavior; review it before applying.

## Troubleshooting

| Observation | What to check |
| --- | --- |
| Profile not found | Configure the exact `audit-lab` profile and use the same user account |
| ExpiredToken / SSO session expired | Sign in again through the configured provider, then rerun |
| Account mismatch | Recheck STS and choose the intended audit profile/account |
| AccessDenied / UnauthorizedOperation | Review the exact operation in scan_errors; check role policy, boundary, SCP, and resource policy with the administrator |
| No resources | Check selected regions and the complete/zero counts; zero alone proves no security conclusion |
| Live mode needs Boto3 | Install `requirements.txt` with the same virtual-environment interpreter |
| Invalid region | Version 1 accepts SDK-known commercial AWS regions; GovCloud and China partitions are outside scope |

S3 ListBuckets includes general purpose buckets. Directory buckets, Outposts, and access points are outside version 1. BucketRegion from the list is preferred; the guide-compatible GetBucketLocation fallback uses the included read permission. AWS recommends HeadBucket for modern region discovery; adopting it would require reviewing permissions and the collection contract separately.
