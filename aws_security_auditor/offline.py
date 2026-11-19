"""Validate fixture envelopes without requiring Boto3."""

import json
import re
from pathlib import Path

from .engine import IDENTIFIERS
from .models import Inventory, KINDS, Scan, timestamp, utcnow


def read_fixture(path: Path) -> Scan:
    def unique_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f"Duplicate JSON field: {key}")
            obj[key] = value
        return obj

    def invalid_constant(value):
        raise ValueError(f"Non-JSON numeric constant: {value}")

    data = json.loads(
        path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_object, parse_constant=invalid_constant
    )
    if not isinstance(data, dict):
        raise ValueError("Fixture root must be an object.")
    if "SecurityGroups" in data:
        # Backward-compatible one-control demonstration from the original guide.
        data = {
            "schema_version": "1.0",
            "account_id": "000000000000",
            "regions": ["us-west-2"],
            "inventories": [
                {
                    "kind": "security_groups",
                    "region": "us-west-2",
                    "complete": True,
                    "records": data["SecurityGroups"],
                }
            ],
            "scope": "security_groups_only",
        }
    if data.get("schema_version") != "1.0":
        raise ValueError("Fixture schema_version must be '1.0'.")
    account = data.get("account_id")
    if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
        raise ValueError("account_id must be a 12-digit string (invented in public fixtures).")
    regions = data.get("regions")
    if (
        not isinstance(regions, list)
        or not regions
        or any(not isinstance(x, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d+", x) for x in regions)
    ):
        raise ValueError("regions must be a nonempty list of region codes.")
    if len(set(regions)) != len(regions):
        raise ValueError("Duplicate regions are not allowed.")
    raw = data.get("inventories")
    if not isinstance(raw, list) or not raw:
        raise ValueError("inventories must be a nonempty list.")
    generated = timestamp(data.get("generated_at", utcnow())).isoformat()
    inventories, scopes = [], set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("Each inventory must be an object.")
        kind, region = entry.get("kind"), entry.get("region")
        if not isinstance(kind, str) or kind not in KINDS or not isinstance(region, str):
            raise ValueError("Unknown inventory kind or invalid region.")
        if (kind == "users" and region != "global") or (kind != "users" and region not in regions):
            raise ValueError("Inventory region must be requested; IAM users use global.")
        if (kind, region) in scopes:
            raise ValueError("Duplicate inventory scope.")
        scopes.add((kind, region))
        records, complete, errors = entry.get("records"), entry.get("complete"), entry.get("errors", [])
        if not isinstance(records, list) or type(complete) is not bool or not isinstance(errors, list):
            raise ValueError("Inventory requires records=list, complete=boolean, errors=list.")
        for error in errors:
            if not isinstance(error, dict) or any(
                not isinstance(error.get(k), str) for k in ("operation", "code")
            ):
                raise ValueError("Each error requires string operation and code fields.")
        ids = set()
        for record in records:
            rid = record.get(IDENTIFIERS[kind]) if isinstance(record, dict) else None
            if not isinstance(rid, str) or not rid.strip() or rid in ids:
                raise ValueError(f"Every {kind} record needs a unique nonempty {IDENTIFIERS[kind]}.")
            ids.add(rid)
        inventories.append(
            Inventory(
                kind,
                region,
                timestamp(entry.get("collected_at", generated)).isoformat(),
                complete and not errors,
                records,
                errors,
            )
        )
    expected = (
        {("security_groups", regions[0])}
        if data.get("scope") == "security_groups_only"
        else (
            {(kind, region) for kind in KINDS if kind != "users" for region in regions}
            | {("users", "global")}
        )
    )
    if scopes != expected:
        raise ValueError(
            "Fixture must explicitly declare every requested inventory, including empty inventories."
        )
    return Scan("offline", account, regions, inventories, generated)
