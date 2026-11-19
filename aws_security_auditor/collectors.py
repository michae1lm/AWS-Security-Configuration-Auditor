"""Read-only AWS collection. Import this module only for live mode."""

import re

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError

from .models import Inventory, Scan, utcnow

SDK_CONFIG = Config(connect_timeout=5, read_timeout=15, retries={"mode": "standard", "total_max_attempts": 4})


def normalize(value):
    """Normalize AWS datetime values recursively, preserving booleans and missing fields."""
    from datetime import datetime

    from .models import timestamp

    if isinstance(value, datetime):
        return timestamp(value).isoformat()
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        return "CredentialsUnavailable"
    return type(exc).__name__


class LiveCollector:
    def __init__(self, session, regions, expected_account, now=None):
        self.session, self.regions, self.expected = session, regions, expected_account
        self.now = (now or utcnow()).isoformat()
        self.inventories, self.skipped, self.clients = [], [], {}

    def client(self, service, region):
        key = (service, region)
        if key not in self.clients:
            self.clients[key] = self.session.client(service, region_name=region, config=SDK_CONFIG)
        return self.clients[key]

    def inventory(self, kind, region):
        inv = Inventory(kind, region, self.now)
        self.inventories.append(inv)
        return inv

    def error(self, inv, operation, code, resource=None):
        inv.complete = False
        # Avoid raw AWS error messages: they can contain account/resource details.
        inv.errors.append(
            {
                "service": inv.service,
                "region": inv.region,
                "operation": operation,
                "code": code,
                "resource": resource or "scope",
            }
        )

    def pages(self, inv, client, operation, field, **kwargs):
        records = []
        try:
            for page in client.get_paginator(operation).paginate(**kwargs):
                items = page.get(field)
                if not isinstance(items, list):
                    self.error(inv, operation, "InvalidResponseShape")
                    continue
                records.extend(items)
        except (ClientError, BotoCoreError) as exc:
            self.error(inv, operation, error_code(exc))
        identifiers = {
            "SecurityGroups": "GroupId",
            "Volumes": "VolumeId",
            "Buckets": "Name",
            "Users": "Arn",
            "AccessKeyMetadata": "AccessKeyId",
            "MFADevices": "SerialNumber",
        }
        return (
            self.unique_records(inv, operation, records, identifiers[field])
            if field in identifiers
            else records
        )

    def unique_records(self, inv, operation, records, identifier):
        unique = {}
        for record in records:
            rid = record.get(identifier) if isinstance(record, dict) else None
            if not isinstance(rid, str) or not rid:
                self.error(inv, operation, "InvalidResourceIdentifier")
                continue
            if identifier == "Arn" and any(
                not isinstance(record.get(k), str) or not record[k] for k in ("UserName", "UserId")
            ):
                self.error(inv, operation, "InvalidUserIdentity", rid)
                continue
            if rid in unique:
                if unique[rid] != record:
                    self.error(inv, operation, "ConflictingDuplicateResource", rid)
                continue
            unique[rid] = record
        return list(unique.values())

    def call(self, inv, client, operation, field=None, absent=None, resource=None, **kwargs):
        try:
            response = getattr(client, operation)(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            code = error_code(exc)
            if absent and code == absent:
                return {"state": "absent"}
            self.error(inv, operation, code, resource)
            return {"state": "unknown"}
        result = (
            response.get(field) if field else {k: v for k, v in response.items() if k != "ResponseMetadata"}
        )
        if field and not isinstance(result, dict):
            self.error(inv, operation, "InvalidResponseShape", resource)
            return {"state": "unknown"}
        return {"state": "present", "data": normalize(result)}

    def ec2(self, region):
        client = self.client("ec2", region)
        for kind, operation, field in (
            ("security_groups", "describe_security_groups", "SecurityGroups"),
            ("instances", "describe_instances", "Reservations"),
            ("volumes", "describe_volumes", "Volumes"),
        ):
            inv = self.inventory(kind, region)
            records = self.pages(inv, client, operation, field)
            if kind == "instances":
                flat = []
                for reservation in records:
                    items = reservation.get("Instances") if isinstance(reservation, dict) else None
                    if not isinstance(items, list):
                        self.error(inv, operation, "InvalidReservationShape")
                    else:
                        flat.extend(items)
                records = self.unique_records(inv, operation, flat, "InstanceId")
            inv.records = normalize(records)

    def s3(self):
        base = self.client("s3", self.regions[0])
        discovery = self.inventory("buckets", self.regions[0])
        buckets = self.pages(discovery, base, "list_buckets", "Buckets", PaginationConfig={"PageSize": 1000})
        by_region = {self.regions[0]: discovery}
        for region in self.regions[1:]:
            by_region[region] = self.inventory("buckets", region)
        if not discovery.complete:
            for region, inv in by_region.items():
                if inv is not discovery:
                    self.error(inv, "list_buckets", "GlobalDiscoveryIncomplete")
        account = self.call(
            discovery,
            self.client("s3control", self.regions[0]),
            "get_public_access_block",
            "PublicAccessBlockConfiguration",
            absent="NoSuchPublicAccessBlockConfiguration",
            AccountId=self.expected,
        )
        if account["state"] == "unknown":
            for inv in by_region.values():
                if inv is not discovery:
                    self.error(inv, "get_public_access_block", "AccountConfigurationUnknown")
        for bucket in buckets:
            name = bucket["Name"]
            if name.endswith("--x-s3"):
                self.skipped.append({"resource": name, "reason": "Directory buckets are unsupported."})
                continue
            # BucketRegion is available in modern paginated ListBuckets responses.
            region = bucket.get("BucketRegion")
            if not region:
                location = self.call(
                    discovery,
                    base,
                    "get_bucket_location",
                    resource=name,
                    Bucket=name,
                    ExpectedBucketOwner=self.expected,
                )
                if location["state"] != "present" or "LocationConstraint" not in location["data"]:
                    if location["state"] == "present":
                        self.error(discovery, "get_bucket_location", "InvalidResponseShape", name)
                    self.skipped.append(
                        {"resource": name, "reason": "Bucket region could not be established."}
                    )
                    for inv in by_region.values():
                        if inv is not discovery:
                            self.error(inv, "get_bucket_location", "BucketRegionUnknown", name)
                    continue
                value = location["data"]["LocationConstraint"]
                region = "us-east-1" if value is None else "eu-west-1" if value == "EU" else value
            if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", region):
                for inv in by_region.values():
                    self.error(inv, "get_bucket_location", "InvalidRegion", name)
                continue
            if region not in by_region:
                self.skipped.append(
                    {"resource": name, "region": region, "reason": "Outside requested regions."}
                )
                continue
            inv, client = by_region[region], self.client("s3", region)
            args = {"Bucket": name, "ExpectedBucketOwner": self.expected}
            inv.records.append(
                {
                    "Name": name,
                    "AccountBlock": account,
                    "BucketBlock": self.call(
                        inv,
                        client,
                        "get_public_access_block",
                        "PublicAccessBlockConfiguration",
                        absent="NoSuchPublicAccessBlockConfiguration",
                        resource=name,
                        **args,
                    ),
                    "Versioning": self.call(inv, client, "get_bucket_versioning", resource=name, **args),
                }
            )

    def iam(self):
        client = self.client("iam", self.regions[0])
        inv = self.inventory("users", "global")
        inv.records = normalize(self.pages(inv, client, "list_users", "Users"))
        no_profile = []
        for user in inv.records:
            name = user["UserName"]
            before = len(inv.errors)
            user["AccessKeys"] = normalize(
                self.pages(inv, client, "list_access_keys", "AccessKeyMetadata", UserName=name)
            )
            user["KeysComplete"] = len(inv.errors) == before
            user["LoginProfile"] = self.call(
                inv,
                client,
                "get_login_profile",
                "LoginProfile",
                absent="NoSuchEntity",
                resource=user["Arn"],
                UserName=name,
            )
            if user["LoginProfile"]["state"] == "absent":
                no_profile.append(user)
                continue
            before = len(inv.errors)
            user["MFADevices"] = normalize(
                self.pages(inv, client, "list_mfa_devices", "MFADevices", UserName=name)
            )
            user["MFAComplete"] = len(inv.errors) == before
        if no_profile:
            before = len(inv.errors)
            fresh = self.pages(inv, client, "list_users", "Users")
            fresh_complete = len(inv.errors) == before
            # UserId detects a deleted-and-recreated username/ARN.
            identities = {(u.get("Arn"), u.get("UserId")) for u in fresh}
            for user in no_profile:
                user["UserStillExists"] = fresh_complete and (user["Arn"], user.get("UserId")) in identities
                if not user["UserStillExists"]:
                    self.error(inv, "get_login_profile", "UserExistenceRace", user["Arn"])

    def collect(self):
        # No inventory calls occur before the expected-account guard.
        try:
            identity = self.client("sts", self.regions[0]).get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            raise ValueError(f"Identity verification failed: {error_code(exc)}") from None
        if identity.get("Account") != self.expected:
            raise ValueError("AWS account mismatch. No resources were collected.")
        for region in self.regions:
            self.ec2(region)
        self.s3()
        self.iam()
        return Scan("live", self.expected, self.regions, self.inventories, self.now, self.skipped)


def collect_live(profile, regions, expected_account):
    try:
        session = boto3.Session(profile_name=profile)
        available = set(session.get_available_regions("ec2", partition_name="aws"))
        if any(region not in available for region in regions):
            raise ValueError(
                "Use supported commercial AWS regions. Other partitions are outside version 1 scope."
            )
        return LiveCollector(session, regions, expected_account).collect()
    except BotoCoreError as exc:
        raise ValueError(f"AWS session setup failed: {error_code(exc)}") from None
