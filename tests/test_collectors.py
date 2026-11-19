from datetime import datetime, timezone
from unittest import mock
import unittest

import boto3
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber

from aws_security_auditor.collectors import LiveCollector, SDK_CONFIG, normalize
from aws_security_auditor.engine import evaluate
from aws_security_auditor.models import Inventory, Scan
from aws_security_auditor.reporting import build_report, exit_code
from aws_security_auditor.rules import console_mfa, public_access_block, versioning

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ACCOUNT = "000000000000"
FIELDS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def aws_user(name="example", uid="AIDA00000000000000000"):
    return {
        "Path": "/",
        "UserName": name,
        "UserId": uid,
        "Arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "CreateDate": NOW,
    }


class CollectorTests(unittest.TestCase):
    """All clients have active Stubbers, so no test performs network requests."""

    def setUp(self):
        self.sdk = boto3.Session(aws_access_key_id="EXAMPLE_ONLY", aws_secret_access_key="EXAMPLE_ONLY")
        self.clients, self.stubs = {}, {}
        self.session = mock.Mock()
        self.session.client.side_effect = self.get_client
        self.collector = LiveCollector(self.session, ["us-west-2"], ACCOUNT, NOW)

    def get_client(self, service, region_name, config=None):
        key = service, region_name
        if key not in self.clients:
            client = self.sdk.client(service, region_name=region_name, config=config)
            stub = Stubber(client)
            stub.activate()
            self.clients[key], self.stubs[key] = client, stub
        return self.clients[key]

    def stub(self, service, region="us-west-2"):
        self.get_client(service, region)
        return self.stubs[service, region]

    def tearDown(self):
        for stub in self.stubs.values():
            try:
                stub.assert_no_pending_responses()
            finally:
                stub.deactivate()

    def empty_ec2(self, region="us-west-2"):
        s = self.stub("ec2", region)
        s.add_response("describe_security_groups", {"SecurityGroups": []}, {})
        s.add_response("describe_instances", {"Reservations": []}, {})
        s.add_response("describe_volumes", {"Volumes": []}, {})

    def test_failure_only_on_second_page(self):
        s = self.stub("ec2")
        s.add_response(
            "describe_security_groups",
            {"SecurityGroups": [{"GroupId": "sg-empty", "IpPermissions": []}], "NextToken": "next"},
            {},
        )
        s.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-failing",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                    }
                ]
            },
            {"NextToken": "next"},
        )
        client = self.get_client("ec2", "us-west-2")
        inv = Inventory("security_groups", "us-west-2", NOW.isoformat())
        inv.records = self.collector.pages(inv, client, "describe_security_groups", "SecurityGroups")
        scan = Scan("live", ACCOUNT, ["us-west-2"], [inv], NOW.isoformat())
        assessments = evaluate(scan, NOW)
        self.assertEqual([a.status for a in assessments], ["PASS", "FAIL"])
        self.assertTrue(inv.complete)

    def test_later_page_failure_retains_first_page(self):
        s = self.stub("ec2")
        s.add_response(
            "describe_security_groups",
            {"SecurityGroups": [{"GroupId": "sg-empty", "IpPermissions": []}], "NextToken": "next"},
            {},
        )
        s.add_client_error(
            "describe_security_groups",
            "AccessDenied",
            "PRIVATE AWS MESSAGE",
            expected_params={"NextToken": "next"},
        )
        inv = Inventory("security_groups", "us-west-2", NOW.isoformat())
        inv.records = self.collector.pages(
            inv, self.get_client("ec2", "us-west-2"), "describe_security_groups", "SecurityGroups"
        )
        self.assertEqual(len(inv.records), 1)
        self.assertFalse(inv.complete)
        self.assertEqual(inv.errors[0]["code"], "AccessDenied")
        self.assertNotIn("PRIVATE", str(inv.errors))

    def test_successful_empty_is_complete(self):
        self.stub("ec2").add_response("describe_volumes", {"Volumes": []}, {})
        inv = Inventory("volumes", "us-west-2", NOW.isoformat())
        self.assertEqual(
            self.collector.pages(inv, self.get_client("ec2", "us-west-2"), "describe_volumes", "Volumes"), []
        )
        self.assertTrue(inv.complete)

    def test_denied_discovery_is_incomplete(self):
        self.stub("ec2").add_client_error("describe_volumes", "UnauthorizedOperation", expected_params={})
        inv = Inventory("volumes", "us-west-2", NOW.isoformat())
        self.assertEqual(
            self.collector.pages(inv, self.get_client("ec2", "us-west-2"), "describe_volumes", "Volumes"), []
        )
        self.assertFalse(inv.complete)
        self.assertEqual(inv.errors[0]["operation"], "describe_volumes")

    def test_all_reservations_flattened(self):
        s = self.stub("ec2")
        s.add_response("describe_security_groups", {"SecurityGroups": []}, {})
        s.add_response(
            "describe_instances",
            {
                "Reservations": [
                    {"Instances": [{"InstanceId": "i-one"}, {"InstanceId": "i-two"}]},
                    {"Instances": [{"InstanceId": "i-three"}]},
                ]
            },
            {},
        )
        s.add_response("describe_volumes", {"Volumes": []}, {})
        self.collector.ec2("us-west-2")
        self.assertEqual(
            [x["InstanceId"] for x in self.collector.inventories[1].records], ["i-one", "i-two", "i-three"]
        )

    def test_exact_absent_block_code(self):
        self.stub("s3").add_client_error(
            "get_public_access_block",
            "NoSuchPublicAccessBlockConfiguration",
            http_status_code=404,
            expected_params={"Bucket": "example-bucket"},
        )
        inv = Inventory("buckets", "us-west-2", NOW.isoformat())
        result = self.collector.call(
            inv,
            self.get_client("s3", "us-west-2"),
            "get_public_access_block",
            "PublicAccessBlockConfiguration",
            absent="NoSuchPublicAccessBlockConfiguration",
            Bucket="example-bucket",
        )
        self.assertEqual(result, {"state": "absent"})
        self.assertTrue(inv.complete)

    def test_denied_block_is_unknown(self):
        self.stub("s3").add_client_error(
            "get_public_access_block",
            "AccessDenied",
            http_status_code=403,
            expected_params={"Bucket": "example-bucket"},
        )
        inv = Inventory("buckets", "us-west-2", NOW.isoformat())
        result = self.collector.call(
            inv,
            self.get_client("s3", "us-west-2"),
            "get_public_access_block",
            "PublicAccessBlockConfiguration",
            absent="NoSuchPublicAccessBlockConfiguration",
            Bucket="example-bucket",
        )
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(inv.complete)

    def test_generic_404_is_not_absent_block(self):
        self.stub("s3").add_client_error(
            "get_public_access_block",
            "NoSuchBucket",
            http_status_code=404,
            expected_params={"Bucket": "example-bucket"},
        )
        inv = Inventory("buckets", "us-west-2", NOW.isoformat())
        result = self.collector.call(
            inv,
            self.get_client("s3", "us-west-2"),
            "get_public_access_block",
            "PublicAccessBlockConfiguration",
            absent="NoSuchPublicAccessBlockConfiguration",
            Bucket="example-bucket",
        )
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(inv.complete)

    def test_s3_pagination_region_and_configuration(self):
        s = self.stub("s3")
        s.add_response(
            "list_buckets",
            {
                "Buckets": [{"Name": "example-west-bucket", "BucketRegion": "us-west-2"}],
                "ContinuationToken": "next",
            },
            {"MaxBuckets": 1000},
        )
        s.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "example-outside-bucket", "BucketRegion": "us-east-2"}]},
            {"MaxBuckets": 1000, "ContinuationToken": "next"},
        )
        self.stub("s3control").add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": dict.fromkeys(FIELDS, True)},
            {"AccountId": ACCOUNT},
        )
        params = {"Bucket": "example-west-bucket", "ExpectedBucketOwner": ACCOUNT}
        s.add_client_error(
            "get_public_access_block", "NoSuchPublicAccessBlockConfiguration", expected_params=params
        )
        s.add_response("get_bucket_versioning", {}, params)
        self.collector.s3()
        inv = self.collector.inventories[0]
        self.assertTrue(inv.complete)
        self.assertEqual(len(inv.records), 1)
        self.assertEqual(public_access_block(inv.records[0])[0], "PASS")
        self.assertEqual(versioning(inv.records[0])[0], "FAIL")
        self.assertEqual(self.collector.skipped[0]["region"], "us-east-2")

    def test_legacy_bucket_locations(self):
        s = self.stub("s3")
        s.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "example-east"}, {"Name": "example-eu"}]},
            {"MaxBuckets": 1000},
        )
        self.stub("s3control").add_client_error(
            "get_public_access_block",
            "NoSuchPublicAccessBlockConfiguration",
            expected_params={"AccountId": ACCOUNT},
        )
        # AWS documents a null location for us-east-1, while the SDK's string
        # shape rejects None in Stubber. Mock this documented parser output.
        with mock.patch.object(
            self.get_client("s3", "us-west-2"),
            "get_bucket_location",
            side_effect=[{"LocationConstraint": None}, {"LocationConstraint": "EU"}],
        ) as location:
            self.collector.s3()
        self.assertEqual(
            location.call_args_list,
            [
                mock.call(Bucket="example-east", ExpectedBucketOwner=ACCOUNT),
                mock.call(Bucket="example-eu", ExpectedBucketOwner=ACCOUNT),
            ],
        )
        self.assertEqual([x["region"] for x in self.collector.skipped], ["us-east-1", "eu-west-1"])

    def test_unknown_bucket_region_marks_every_region_incomplete(self):
        self.collector.regions.append("us-east-1")
        s = self.stub("s3")
        s.add_response("list_buckets", {"Buckets": [{"Name": "example-denied"}]}, {"MaxBuckets": 1000})
        self.stub("s3control").add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": dict.fromkeys(FIELDS, True)},
            {"AccountId": ACCOUNT},
        )
        s.add_client_error(
            "get_bucket_location",
            "AccessDenied",
            expected_params={"Bucket": "example-denied", "ExpectedBucketOwner": ACCOUNT},
        )
        self.collector.s3()
        self.assertTrue(all(not inv.complete for inv in self.collector.inventories))

    def test_denied_versioning_does_not_erase_block_result(self):
        s = self.stub("s3")
        s.add_response(
            "list_buckets",
            {"Buckets": [{"Name": "example-bucket", "BucketRegion": "us-west-2"}]},
            {"MaxBuckets": 1000},
        )
        self.stub("s3control").add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": dict.fromkeys(FIELDS, True)},
            {"AccountId": ACCOUNT},
        )
        params = {"Bucket": "example-bucket", "ExpectedBucketOwner": ACCOUNT}
        s.add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": dict.fromkeys(FIELDS, False)},
            params,
        )
        s.add_client_error("get_bucket_versioning", "AccessDenied", expected_params=params)
        self.collector.s3()
        inv = self.collector.inventories[0]
        self.assertFalse(inv.complete)
        self.assertEqual(public_access_block(inv.records[0])[0], "PASS")
        self.assertEqual(versioning(inv.records[0])[0], "UNKNOWN")

    def test_iam_keys_paginated_and_no_profile_rechecked(self):
        s, user = self.stub("iam"), aws_user()
        s.add_response("list_users", {"Users": [user], "IsTruncated": False}, {})
        s.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "example",
                        "AccessKeyId": "AKIA0000000000000001",
                        "Status": "Active",
                        "CreateDate": NOW,
                    }
                ],
                "IsTruncated": True,
                "Marker": "next",
            },
            {"UserName": "example"},
        )
        s.add_response(
            "list_access_keys",
            {
                "AccessKeyMetadata": [
                    {
                        "UserName": "example",
                        "AccessKeyId": "AKIA0000000000000002",
                        "Status": "Inactive",
                        "CreateDate": NOW,
                    }
                ],
                "IsTruncated": False,
            },
            {"UserName": "example", "Marker": "next"},
        )
        s.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": "example"})
        s.add_response("list_users", {"Users": [user], "IsTruncated": False}, {})
        self.collector.iam()
        record = self.collector.inventories[0].records[0]
        self.assertEqual(len(record["AccessKeys"]), 2)
        self.assertTrue(record["KeysComplete"])
        self.assertEqual(console_mfa(record)[0], "NOT_APPLICABLE")
        self.assertIsInstance(record["AccessKeys"][0]["CreateDate"], str)

    def test_deleted_and_recreated_user_race(self):
        s, user = self.stub("iam"), aws_user()
        s.add_response("list_users", {"Users": [user], "IsTruncated": False}, {})
        s.add_response(
            "list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False}, {"UserName": "example"}
        )
        s.add_client_error("get_login_profile", "NoSuchEntity", expected_params={"UserName": "example"})
        s.add_response(
            "list_users", {"Users": [aws_user(uid="AIDA11111111111111111")], "IsTruncated": False}, {}
        )
        self.collector.iam()
        inv = self.collector.inventories[0]
        self.assertEqual(console_mfa(inv.records[0])[0], "UNKNOWN")
        self.assertFalse(inv.complete)
        self.assertEqual(inv.errors[0]["code"], "UserExistenceRace")

    def test_paginated_mfa_devices(self):
        s, user = self.stub("iam"), aws_user()
        s.add_response("list_users", {"Users": [user], "IsTruncated": False}, {})
        s.add_response(
            "list_access_keys", {"AccessKeyMetadata": [], "IsTruncated": False}, {"UserName": "example"}
        )
        s.add_response(
            "get_login_profile",
            {"LoginProfile": {"UserName": "example", "CreateDate": NOW}},
            {"UserName": "example"},
        )
        s.add_response(
            "list_mfa_devices",
            {"MFADevices": [], "IsTruncated": True, "Marker": "next"},
            {"UserName": "example"},
        )
        s.add_response(
            "list_mfa_devices",
            {
                "MFADevices": [{"UserName": "example", "SerialNumber": "example-device", "EnableDate": NOW}],
                "IsTruncated": False,
            },
            {"UserName": "example", "Marker": "next"},
        )
        self.collector.iam()
        self.assertEqual(console_mfa(self.collector.inventories[0].records[0])[0], "PASS")

    def test_two_regions_global_iam_once(self):
        self.collector.regions.append("us-east-1")
        self.stub("sts").add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        self.empty_ec2()
        self.empty_ec2("us-east-1")
        self.stub("s3").add_response("list_buckets", {"Buckets": []}, {"MaxBuckets": 1000})
        self.stub("s3control").add_response(
            "get_public_access_block",
            {"PublicAccessBlockConfiguration": dict.fromkeys(FIELDS, True)},
            {"AccountId": ACCOUNT},
        )
        self.stub("iam").add_response("list_users", {"Users": [], "IsTruncated": False}, {})
        scan = self.collector.collect()
        self.assertEqual(len([inv for inv in scan.inventories if inv.kind == "users"]), 1)
        report = build_report(scan, evaluate(scan, NOW))
        self.assertEqual(exit_code(report), 0)
        self.assertEqual(report["coverage"]["resource_count"], 0)
        self.assertEqual(report["coverage"]["completed_regions"], ["us-west-2", "us-east-1"])

    def test_account_mismatch_stops_before_resource_clients(self):
        self.stub("sts").add_response("get_caller_identity", {"Account": "111111111111"}, {})
        with self.assertRaisesRegex(ValueError, "account mismatch"):
            self.collector.collect()
        self.assertEqual(self.collector.inventories, [])
        self.assertEqual(list(self.clients), [("sts", "us-west-2")])

    def test_expired_identity_credentials(self):
        self.stub("sts").add_client_error("get_caller_identity", "ExpiredToken", expected_params={})
        with self.assertRaisesRegex(ValueError, "ExpiredToken"):
            self.collector.collect()
        self.assertEqual(self.collector.inventories, [])

    def test_credential_provider_error(self):
        client = self.get_client("sts", "us-west-2")
        with mock.patch.object(client, "get_caller_identity", side_effect=NoCredentialsError()):
            with self.assertRaisesRegex(ValueError, "CredentialsUnavailable"):
                self.collector.collect()

    def test_bounded_retry_configuration(self):
        self.assertEqual(SDK_CONFIG.retries["total_max_attempts"], 4)
        self.assertEqual(SDK_CONFIG.connect_timeout, 5)
        self.assertEqual(SDK_CONFIG.read_timeout, 15)

    def test_timestamp_normalization_preserves_false_and_missing(self):
        self.assertEqual(
            normalize({"date": NOW, "encrypted": False}), {"date": NOW.isoformat(), "encrypted": False}
        )

    def test_repeated_volume_is_counted_once(self):
        inv = Inventory("volumes", "us-west-2", NOW.isoformat())
        records = [{"VolumeId": "vol-example", "Encrypted": True}] * 2
        self.assertEqual(len(self.collector.unique_records(inv, "describe_volumes", records, "VolumeId")), 1)
        self.assertTrue(inv.complete)

    def test_conflicting_duplicate_is_incomplete(self):
        inv = Inventory("volumes", "us-west-2", NOW.isoformat())
        records = [
            {"VolumeId": "vol-example", "Encrypted": True},
            {"VolumeId": "vol-example", "Encrypted": False},
        ]
        self.assertEqual(len(self.collector.unique_records(inv, "describe_volumes", records, "VolumeId")), 1)
        self.assertFalse(inv.complete)

    def test_invalid_live_identifier_is_scope_error(self):
        inv = Inventory("volumes", "us-west-2", NOW.isoformat())
        self.assertEqual(self.collector.unique_records(inv, "describe_volumes", [{}], "VolumeId"), [])
        self.assertFalse(inv.complete)
