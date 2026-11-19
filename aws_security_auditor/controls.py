"""Control text is shared by the evaluator and generated reports."""

CONTROLS = {
    "EC2-001": (
        "Restrict unrestricted TCP administrative ingress",
        "HIGH",
        "Restrict TCP 22/3389 to approved sources, or use a managed administrative access method.",
        "Unrestricted administrative ingress expands exposure; routing and actual reachability are not evaluated.",
        "Re-read inbound rules and rerun EC2-001; separately evaluate network reachability.",
    ),
    "EC2-002": (
        "Require IMDSv2 when instance metadata is enabled",
        "MEDIUM",
        "Test application compatibility, then require IMDSv2, or disable an unused metadata endpoint.",
        "Optional tokens allow IMDSv1; this observation does not establish credential theft.",
        "Wait for MetadataOptions.State=applied, re-read configuration, and rerun EC2-002.",
    ),
    "EBS-001": (
        "Encrypt EBS volumes",
        "MEDIUM",
        "Plan an encrypted snapshot/volume replacement and migrate attachments after backup and validation.",
        "The volume reports encryption disabled, reducing at-rest data protection.",
        "Check encryption on the replacement, validate the migration, and rerun EBS-001.",
    ),
    "S3-001": (
        "Enable all effective S3 public access block settings",
        "MEDIUM",
        "Review required access, then enable the missing account or bucket public access block settings.",
        "A public access block baseline gap is present; this does not establish public access to objects.",
        "Re-read account and bucket settings and rerun S3-001; separately review authorization policies.",
    ),
    "S3-002": (
        "Enable bucket versioning",
        "LOW",
        "Review recovery and storage requirements, then enable bucket versioning where appropriate.",
        "Recovery from accidental deletion or overwrite is less protected under this versioning baseline.",
        "Re-read bucket versioning and rerun S3-002. Consider lifecycle management separately.",
    ),
    "IAM-001": (
        "Review active IAM user key age",
        "MEDIUM",
        "Review the active key, migrate consumers to temporary credentials where possible, or rotate and verify consumers.",
        "An active key exceeds the configured review threshold; age alone does not establish compromise.",
        "Validate consumer migration, retire the old key separately, and rerun IAM-001.",
    ),
    "IAM-002": (
        "Register MFA for IAM console users",
        "HIGH",
        "Register an appropriate MFA device and separately review authentication enforcement.",
        "A console user has no registered MFA device; session-level MFA use is outside this check.",
        "Re-list the user's registered MFA devices and rerun IAM-002.",
    ),
}

BLOCK_FIELDS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
