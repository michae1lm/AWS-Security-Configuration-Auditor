"""Shared, SDK-independent inventory and assessment types."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal

Status = Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]


class RuleResult(tuple):
    """A (status, evidence) pair with separate rule-input completeness.

    Proven failure and incomplete input can coexist in a compound rule.
    """

    def __new__(cls, status, evidence, complete):
        result = super().__new__(cls, (status, evidence))
        result.complete = complete
        return result


KINDS = {
    "security_groups": ("EC2", "AWS::EC2::SecurityGroup"),
    "instances": ("EC2", "AWS::EC2::Instance"),
    "volumes": ("EBS", "AWS::EC2::Volume"),
    "buckets": ("S3", "AWS::S3::Bucket"),
    "users": ("IAM", "AWS::IAM::User"),
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: object) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware ISO 8601 timestamp is required.")
    return value.astimezone(timezone.utc)


@dataclass
class Inventory:
    kind: str
    region: str
    collected_at: str
    complete: bool = True
    records: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    @property
    def service(self) -> str:
        return KINDS[self.kind][0]


@dataclass
class Scan:
    mode: str
    account_id: str
    regions: list[str]
    inventories: list[Inventory]
    generated_at: str
    skipped: list[dict] = field(default_factory=list)


@dataclass
class Assessment:
    id: str
    check_id: str
    title: str
    account_id: str
    region: str
    resource_id: str
    resource_type: str
    service: str
    status: Status
    severity: str
    evidence: list[str]
    recommendation: str
    risk: str
    verification: str
    collected_at: str
    collection_complete: bool
    evaluation_complete: bool


def stable_id(account: str, region: str, resource: str, check: str) -> str:
    return sha256("\x00".join((account, region, resource, check)).encode()).hexdigest()[:32]
