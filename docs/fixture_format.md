# Offline input contract

Offline mode never creates an AWS session. It reads a local UTF-8 JSON file (a UTF-8 BOM is accepted) and validates the inventory envelope. These fixtures must contain invented records or private sanitized captures; do not save credentials in them.

## Full seven-control envelope

Use `fixtures/demo.json` as the runnable complete example. Its top-level shape is:

```json
{
  "schema_version": "1.0",
  "account_id": "000000000000",
  "regions": ["us-west-2"],
  "generated_at": "2026-11-18T12:00:00+00:00",
  "inventories": [
    {"kind": "security_groups", "region": "us-west-2", "complete": true, "records": [], "errors": []},
    {"kind": "instances", "region": "us-west-2", "complete": true, "records": [], "errors": []},
    {"kind": "volumes", "region": "us-west-2", "complete": true, "records": [], "errors": []},
    {"kind": "buckets", "region": "us-west-2", "complete": true, "records": [], "errors": []},
    {"kind": "users", "region": "global", "complete": true, "records": [], "errors": []}
  ]
}
```

For each requested region, explicitly declare security_groups, instances, volumes, and buckets, including successful empty inventories. Declare users exactly once in global scope. Omitting a whole inventory is an input error, not a quiet zero count. Each envelope can override collected_at with a timezone-aware timestamp.

| Inventory | Required identifier | Other rule input |
| --- | --- | --- |
| security_groups | GroupId string | AWS-shaped IpPermissions |
| instances | InstanceId string | AWS-shaped State and MetadataOptions |
| volumes | VolumeId string | Encrypted and observed Attachments |
| buckets | Name string | AccountBlock, BucketBlock, Versioning |
| users | Arn string | AccessKeys, KeysComplete, LoginProfile, MFADevices, MFAComplete, UserStillExists |

Identifiers must be nonempty and unique per envelope. Invalid record-level configuration types are preserved for the rule to return UNKNOWN. An invalid/missing resource identifier prevents a trustworthy resource assessment, so it is an input error.

## Configuration read states

```json
{"state": "present", "data": {"Status": "Enabled"}}
```

```json
{"state": "absent"}
```

```json
{"state": "unknown"}
```

S3 account/bucket block `data` contains the four exact Boolean fields. Only a verified absence maps to four False fields. Versioning present data with no Status means successfully observed never-enabled versioning, which fails the recovery baseline. Unknown is not the same as a successful empty object.

IAM LoginProfile present data includes UserName. An absent profile requires UserStillExists=true from a fresh matching identity listing to be NOT_APPLICABLE. MFADevices is a list of registered device objects with nonempty SerialNumber; MFAComplete must be true before an empty list proves no registered device.

AccessKeys contains AccessKeyId, Status, and timezone-aware CreateDate per key. KeysComplete=true with [] establishes no user keys. Missing/malformed/partial inventories produce user-level UNKNOWN scope. Unknown access-key status, malformed timestamps, and future dates remain UNKNOWN. The report masks the displayed key ID.

## Scope errors

```json
{
  "kind": "users",
  "region": "global",
  "complete": false,
  "records": [],
  "errors": [{"operation": "list_users", "code": "AccessDenied", "resource": "scope"}]
}
```

Every error requires string operation and code. Any errors override a contradictory complete=true flag. complete=false without errors remains incomplete. Offline error labels are fixture data, not evidence of an actual AWS request.

## Original one-control format

For compatibility with the starter guide, `{"SecurityGroups": [...]}` selects EC2-001 only. The report explicitly lists that one enabled check, uses invented account 000000000000, and assigns us-west-2 fixture scope. It is not a full seven-control scan. `fixtures/security_groups.json`, `pass.json`, and `fail.json` use this format.

## Deterministic age evaluation

The full demo fixes generated_at to November 18, 2026, at 12:00 UTC. That is also the default offline evaluation time, making the key-age examples reproducible later. `--now` overrides it for experiments. Every supplied timestamp must include timezone information. For the one-control legacy format, generated_at defaults to the run time because no key-age rule is enabled.
