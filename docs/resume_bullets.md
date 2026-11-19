# Resume wording matched to the evidence

Project title: **Python AWS Security Configuration Auditor**

After you run the program, review the code, and can explain it, the implemented and locally verified capabilities support:

- Developed a Python/Boto3 configuration auditor with seven EC2, EBS, S3, and IAM controls, producing JSON and Markdown evidence, remediation guidance, and explicit incomplete-scan reporting.
- Tested offline rule logic and simulated AWS collection for IPv6 ingress, paginated inventory, denied API requests, MFA registration, and precise access-key age boundaries.

The exact test count and measured statement coverage are in `validation.md`. Include those numbers only while they match your current repository and test run.

After real-account validation, you may add:

- Validated configuration findings against a personal AWS lab and documented expected versus observed results across the available resource types.

Use that bullet only after completing the live validation table. Do not claim a deployed cloud service, real-account scan count, verified remediation, time savings, or hosted CI result until those outcomes exist. Mocked responses and invented fixtures are not scanned cloud resources.

For your security engineering/cloud security focus, emphasize the collector/rule separation, permissions, input validation, API error handling, tests, and readable evidence. Keep a single GitHub profile link in the resume header and pin the repository there.
