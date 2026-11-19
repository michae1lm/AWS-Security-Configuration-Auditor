"""Apply the same rules to offline and live inventories."""

from .controls import CONTROLS
from .models import Assessment, KINDS, RuleResult, Scan, stable_id
from .rules import (
    admin_ingress,
    console_mfa,
    ebs_encryption,
    imdsv2,
    key_age,
    public_access_block,
    versioning,
)

IDENTIFIERS = {
    "security_groups": "GroupId",
    "instances": "InstanceId",
    "volumes": "VolumeId",
    "buckets": "Name",
    "users": "Arn",
}
CHECKS = {
    "security_groups": ["EC2-001"],
    "instances": ["EC2-002"],
    "volumes": ["EBS-001"],
    "buckets": ["S3-001", "S3-002"],
    "users": ["IAM-001", "IAM-002"],
}


def evaluate(scan: Scan, now, max_age_days: int = 90) -> list[Assessment]:
    results = []
    for inv in scan.inventories:
        for record in inv.records:
            resource = record[IDENTIFIERS[inv.kind]]

            def add(check, outcome, internal=None, display=None, resource_type=None):
                title, severity, recommendation, risk, verification = CONTROLS[check]
                status, evidence = outcome
                results.append(
                    Assessment(
                        id=stable_id(scan.account_id, inv.region, internal or resource, check),
                        check_id=check,
                        title=title,
                        account_id=scan.account_id,
                        region=inv.region,
                        resource_id=display or resource,
                        resource_type=resource_type or KINDS[inv.kind][1],
                        service=inv.service,
                        status=status,
                        severity=severity,
                        evidence=evidence,
                        recommendation=recommendation,
                        risk=risk,
                        verification=verification,
                        collected_at=inv.collected_at,
                        collection_complete=inv.complete,
                        evaluation_complete=(
                            outcome.complete if isinstance(outcome, RuleResult) else status != "UNKNOWN"
                        ),
                    )
                )

            if inv.kind == "security_groups":
                add("EC2-001", admin_ingress(record))
            elif inv.kind == "instances":
                add("EC2-002", imdsv2(record))
            elif inv.kind == "volumes":
                add("EBS-001", ebs_encryption(record))
            elif inv.kind == "buckets":
                add("S3-001", public_access_block(record))
                add("S3-002", versioning(record))
            elif inv.kind == "users":
                add("IAM-002", console_mfa(record))
                keys = record.get("AccessKeys")
                if not isinstance(keys, list):
                    add("IAM-001", ("UNKNOWN", ["Access key inventory is missing or malformed."]))
                    continue
                invalid = False
                seen = set()
                for key in keys:
                    kid = key.get("AccessKeyId") if isinstance(key, dict) else None
                    if not isinstance(kid, str) or not kid or kid in seen:
                        invalid = True
                        continue
                    seen.add(kid)
                    add(
                        "IAM-001",
                        key_age(key, now, max_age_days),
                        internal=f"{resource}/key/{kid}",
                        display=f"{resource}/key/***{kid[-4:]}",
                        resource_type="AWS::IAM::AccessKey",
                    )
                if invalid or record.get("KeysComplete") is not True:
                    add(
                        "IAM-001",
                        (
                            "UNKNOWN",
                            ["Access key inventory is partial, malformed, or contains invalid identifiers."],
                        ),
                    )
    return sorted(results, key=lambda a: (a.service, a.region, a.resource_id, a.check_id, a.id))
