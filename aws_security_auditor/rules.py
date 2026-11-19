"""Pure security rules. None of these functions uses an SDK or network."""

from datetime import datetime, timedelta
from ipaddress import ip_network

from .controls import BLOCK_FIELDS
from .models import RuleResult, timestamp


def admin_ingress(group: dict) -> tuple[str, list[str]]:
    permissions = group.get("IpPermissions")
    if not isinstance(permissions, list):
        return "UNKNOWN", ["IpPermissions is missing or is not a list."]
    evidence, incomplete = [], False
    for rule in permissions:
        if not isinstance(rule, dict):
            incomplete = True
            continue
        protocol = rule.get("IpProtocol")
        if not isinstance(protocol, str) or not protocol:
            incomplete = True
            continue
        if protocol not in {"tcp", "6", "-1"}:
            # Valid other protocols do not permit TCP administrative traffic.
            if protocol not in {"udp", "icmp", "icmpv6"}:
                try:
                    if not 0 <= int(protocol) <= 255:
                        incomplete = True
                except ValueError:
                    incomplete = True
            continue
        if protocol == "-1":
            ports = [22, 3389]
        else:
            start, end = rule.get("FromPort"), rule.get("ToPort")
            if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
                incomplete = True
                continue
            ports = [p for p in (22, 3389) if start <= p <= end]
        sources_present = any(
            k in rule for k in ("IpRanges", "Ipv6Ranges", "UserIdGroupPairs", "PrefixListIds")
        )
        if not sources_present:
            incomplete = True
        for name, cidr_key, version in (("IpRanges", "CidrIp", 4), ("Ipv6Ranges", "CidrIpv6", 6)):
            ranges = rule.get(name, [])
            if not isinstance(ranges, list):
                incomplete = True
                continue
            for source in ranges:
                try:
                    cidr = source.get(cidr_key) if isinstance(source, dict) else None
                    if not isinstance(cidr, str):
                        raise ValueError
                    network = ip_network(cidr, strict=False)
                    if network.version != version:
                        raise ValueError
                except ValueError:
                    incomplete = True
                    continue
                if network.prefixlen == 0 and ports:
                    evidence.append(f"{network} permits TCP ports {ports}.")
        for name in ("UserIdGroupPairs", "PrefixListIds"):
            if name in rule and (
                not isinstance(rule[name], list) or any(not isinstance(x, dict) for x in rule[name])
            ):
                incomplete = True
    status = "FAIL" if evidence else "UNKNOWN" if incomplete else "PASS"
    if incomplete:
        evidence.append("Some inbound permission fields are invalid or incomplete.")
    if not evidence:
        evidence.append("No explicit /0 TCP ingress covering 22 or 3389 was observed.")
    return RuleResult(status, evidence, complete=not incomplete)


def imdsv2(instance: dict) -> tuple[str, list[str]]:
    state = instance.get("State")
    state = state.get("Name") if isinstance(state, dict) else None
    opts = instance.get("MetadataOptions")
    opts = opts if isinstance(opts, dict) else {}
    endpoint, tokens, applied = (opts.get(k) for k in ("HttpEndpoint", "HttpTokens", "State"))
    evidence = [
        f"Instance state={state!r}; HttpEndpoint={endpoint!r}; HttpTokens={tokens!r}; configuration state={applied!r}."
    ]
    if state in ("terminated", "shutting-down"):
        return "NOT_APPLICABLE", evidence
    if state not in ("pending", "running", "stopping", "stopped") or applied != "applied":
        return "UNKNOWN", evidence
    if endpoint == "disabled":
        return "PASS", evidence
    if endpoint == "enabled" and tokens in ("required", "optional"):
        return "PASS" if tokens == "required" else "FAIL", evidence
    return "UNKNOWN", evidence


def ebs_encryption(volume: dict) -> tuple[str, list[str]]:
    encrypted = volume.get("Encrypted")
    attachments = volume.get("Attachments", "unknown")
    evidence = [f"Encrypted={encrypted!r}; attachments={attachments!r}."]
    return ("PASS" if encrypted is True else "FAIL" if encrypted is False else "UNKNOWN"), evidence


def block_values(result: object) -> dict:
    if not isinstance(result, dict):
        return dict.fromkeys(BLOCK_FIELDS)
    if result.get("state") == "absent":
        return dict.fromkeys(BLOCK_FIELDS, False)
    data = result.get("data")
    if result.get("state") != "present" or not isinstance(data, dict):
        return dict.fromkeys(BLOCK_FIELDS)
    return {k: data[k] if type(data.get(k)) is bool else None for k in BLOCK_FIELDS}


def public_access_block(bucket: dict) -> tuple[str, list[str]]:
    account, local = block_values(bucket.get("AccountBlock")), block_values(bucket.get("BucketBlock"))
    combined, evidence = [], []
    for key in BLOCK_FIELDS:
        a, b = account[key], local[key]
        effective = True if a is True or b is True else False if a is False and b is False else None
        combined.append(effective)
        evidence.append(f"{key}: account={a!r}, bucket={b!r}, effective={effective!r}.")
    return RuleResult(
        "FAIL" if False in combined else "UNKNOWN" if None in combined else "PASS",
        evidence,
        complete=None not in combined,
    )


def versioning(bucket: dict) -> tuple[str, list[str]]:
    result = bucket.get("Versioning")
    if (
        not isinstance(result, dict)
        or result.get("state") != "present"
        or not isinstance(result.get("data"), dict)
    ):
        return "UNKNOWN", ["Bucket versioning could not be read."]
    data = result["data"]
    status = data.get("Status")
    outcome = (
        "PASS"
        if status == "Enabled"
        else "FAIL"
        if "Status" not in data or status == "Suspended"
        else "UNKNOWN"
    )
    return outcome, [f"Versioning Status={status!r}; successful configuration read."]


def key_age(key: dict, now: datetime, max_age_days: int) -> tuple[str, list[str]]:
    status = key.get("Status")
    if status in ("Inactive", "Expired"):
        return "NOT_APPLICABLE", [f"Key status={status}; active-key baseline does not apply."]
    if status != "Active":
        return "UNKNOWN", [f"Unrecognized or missing key status: {status!r}."]
    try:
        created, now = timestamp(key.get("CreateDate")), timestamp(now)
        age = now - created
        if age < timedelta(0):
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        return "UNKNOWN", ["Key creation time is invalid, timezone-naive, missing, or in the future."]
    return ("FAIL" if age > timedelta(days=max_age_days) else "PASS"), [
        f"Active key created={created.isoformat()}; age_seconds={age.total_seconds():.6f}; threshold_days={max_age_days}."
    ]


def console_mfa(user: dict) -> tuple[str, list[str]]:
    profile = user.get("LoginProfile")
    if not isinstance(profile, dict):
        return "UNKNOWN", ["Console login profile is unknown."]
    if profile.get("state") == "absent":
        if user.get("UserStillExists") is True:
            return "NOT_APPLICABLE", ["No console profile; fresh IAM listing still contains the same user."]
        return "UNKNOWN", ["No console profile and user existence is inconsistent or unverified."]
    if (
        profile.get("state") != "present"
        or not isinstance(profile.get("data"), dict)
        or not isinstance(profile["data"].get("UserName"), str)
        or not profile["data"]["UserName"]
    ):
        return "UNKNOWN", ["Console login profile could not be established."]
    devices = user.get("MFADevices")
    if not isinstance(devices, list) or any(
        not isinstance(x, dict) or not isinstance(x.get("SerialNumber"), str) or not x["SerialNumber"]
        for x in devices
    ):
        return "UNKNOWN", ["Registered MFA device data is missing or malformed."]
    if devices:
        return "PASS", [f"Console profile present; registered MFA device count={len(devices)}."]
    if user.get("MFAComplete") is not True:
        return "UNKNOWN", ["Console profile present; MFA device inventory is incomplete."]
    return "FAIL", ["Console profile present; complete MFA device inventory is empty."]
