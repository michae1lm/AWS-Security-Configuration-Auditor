import copy
from datetime import datetime, timedelta, timezone
import unittest

from aws_security_auditor.controls import BLOCK_FIELDS
from aws_security_auditor.rules import (
    admin_ingress,
    console_mfa,
    ebs_encryption,
    imdsv2,
    key_age,
    public_access_block,
    versioning,
)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def group(protocol="tcp", start=22, end=22, cidr="0.0.0.0/0"):
    field, key = ("Ipv6Ranges", "CidrIpv6") if ":" in cidr else ("IpRanges", "CidrIp")
    return {
        "GroupId": "sg-example",
        "IpPermissions": [{"IpProtocol": protocol, "FromPort": start, "ToPort": end, field: [{key: cidr}]}],
    }


def present(data):
    return {"state": "present", "data": data}


def block(value):
    return present(dict.fromkeys(BLOCK_FIELDS, value))


class AdminIngressTests(unittest.TestCase):
    def test_public_ssh(self):
        status, evidence = admin_ingress(group())
        self.assertEqual(status, "FAIL")
        self.assertIn("0.0.0.0/0", evidence[0])
        self.assertIn("22", evidence[0])

    def test_public_ipv6_rdp(self):
        self.assertEqual(admin_ingress(group(start=3389, end=3389, cidr="::/0"))[0], "FAIL")

    def test_all_protocols(self):
        self.assertEqual(admin_ingress(group("-1"))[0], "FAIL")

    def test_numeric_tcp_range(self):
        self.assertEqual(admin_ingress(group("6", 20, 30))[0], "FAIL")

    def test_range_contains_rdp(self):
        self.assertEqual(admin_ingress(group(start=3380, end=3390, cidr="::/0"))[0], "FAIL")

    def test_restricted_source(self):
        self.assertEqual(admin_ingress(group(cidr="203.0.113.10/32"))[0], "PASS")

    def test_https(self):
        self.assertEqual(admin_ingress(group(start=443, end=443))[0], "PASS")

    def test_udp(self):
        self.assertEqual(admin_ingress(group("udp"))[0], "PASS")

    def test_empty_permissions(self):
        self.assertEqual(admin_ingress({"IpPermissions": []})[0], "PASS")

    def test_missing_permissions(self):
        self.assertEqual(admin_ingress({})[0], "UNKNOWN")

    def test_invalid_port(self):
        for value in ("22", None, True, -1, 65536, []):
            with self.subTest(value=value):
                self.assertEqual(admin_ingress(group(start=value))[0], "UNKNOWN")

    def test_reversed_port_range(self):
        self.assertEqual(admin_ingress(group(start=100, end=22))[0], "UNKNOWN")

    def test_two_findings_one_assessment(self):
        item = group()
        item["IpPermissions"] += group(start=3389, end=3389, cidr="::/0")["IpPermissions"]
        status, evidence = admin_ingress(item)
        self.assertEqual(status, "FAIL")
        self.assertEqual(len(evidence), 2)

    def test_proven_failure_has_priority_over_missing_data(self):
        item = group()
        item["IpPermissions"].append({})
        status, evidence = admin_ingress(item)
        self.assertEqual(status, "FAIL")
        self.assertIn("incomplete", evidence[-1])

    def test_malformed_rule(self):
        self.assertEqual(admin_ingress({"IpPermissions": [None]})[0], "UNKNOWN")

    def test_malformed_ranges(self):
        for value in (None, [None], [{"CidrIp": "bad"}], [{"CidrIp": "::/0"}], "0.0.0.0/0"):
            with self.subTest(value=value):
                item = group()
                item["IpPermissions"][0]["IpRanges"] = value
                self.assertEqual(admin_ingress(item)[0], "UNKNOWN")

    def test_missing_sources(self):
        item = group()
        del item["IpPermissions"][0]["IpRanges"]
        self.assertEqual(admin_ingress(item)[0], "UNKNOWN")

    def test_prefix_lists_are_not_expanded(self):
        item = group()
        rule = item["IpPermissions"][0]
        del rule["IpRanges"]
        rule["PrefixListIds"] = [{"PrefixListId": "pl-example"}]
        self.assertEqual(admin_ingress(item)[0], "PASS")

    def test_invalid_protocol(self):
        for protocol in (None, [], "999", "nonsense"):
            item = group()
            item["IpPermissions"][0]["IpProtocol"] = protocol
            self.assertEqual(admin_ingress(item)[0], "UNKNOWN")


class InstanceTests(unittest.TestCase):
    def instance(self, tokens="required", endpoint="enabled", config="applied", state="running"):
        return {
            "State": {"Name": state},
            "MetadataOptions": {"HttpTokens": tokens, "HttpEndpoint": endpoint, "State": config},
        }

    def test_v2_required(self):
        self.assertEqual(imdsv2(self.instance())[0], "PASS")

    def test_v1_allowed(self):
        self.assertEqual(imdsv2(self.instance(tokens="optional"))[0], "FAIL")

    def test_disabled_endpoint(self):
        self.assertEqual(imdsv2(self.instance(endpoint="disabled", tokens=None))[0], "PASS")

    def test_pending_is_unknown_even_if_disabled(self):
        self.assertEqual(imdsv2(self.instance(endpoint="disabled", config="pending"))[0], "UNKNOWN")

    def test_stopped_in_scope(self):
        self.assertEqual(imdsv2(self.instance(state="stopped", tokens="optional"))[0], "FAIL")

    def test_terminated_not_applicable(self):
        for state in ("terminated", "shutting-down"):
            self.assertEqual(imdsv2(self.instance(state=state))[0], "NOT_APPLICABLE")

    def test_missing_options(self):
        self.assertEqual(imdsv2({"State": {"Name": "running"}})[0], "UNKNOWN")

    def test_unrecognized_fields(self):
        for kwargs in ({"tokens": "new"}, {"endpoint": "new"}, {"state": []}, {"config": {}}):
            self.assertEqual(imdsv2(self.instance(**kwargs))[0], "UNKNOWN")


class VolumeTests(unittest.TestCase):
    def test_encrypted(self):
        self.assertEqual(ebs_encryption({"Encrypted": True})[0], "PASS")

    def test_unencrypted_attached(self):
        result = ebs_encryption({"Encrypted": False, "Attachments": [{"InstanceId": "i-example"}]})
        self.assertEqual(result[0], "FAIL")
        self.assertIn("i-example", result[1][0])

    def test_unattached_still_in_scope(self):
        self.assertEqual(ebs_encryption({"Encrypted": False, "Attachments": []})[0], "FAIL")

    def test_missing_and_invalid_are_unknown(self):
        for value in (None, "false", 0, 1, []):
            self.assertEqual(ebs_encryption({"Encrypted": value})[0], "UNKNOWN")


class BucketTests(unittest.TestCase):
    def test_account_covers_bucket_gap(self):
        self.assertEqual(
            public_access_block({"AccountBlock": block(True), "BucketBlock": block(False)})[0], "PASS"
        )

    def test_bucket_covers_missing_account(self):
        self.assertEqual(
            public_access_block({"AccountBlock": {"state": "absent"}, "BucketBlock": block(True)})[0], "PASS"
        )

    def test_true_covers_unknown(self):
        self.assertEqual(
            public_access_block({"AccountBlock": block(True), "BucketBlock": {"state": "unknown"}})[0], "PASS"
        )

    def test_known_gap(self):
        self.assertEqual(
            public_access_block({"AccountBlock": block(False), "BucketBlock": block(False)})[0], "FAIL"
        )

    def test_false_and_unknown_is_unknown(self):
        self.assertEqual(
            public_access_block({"AccountBlock": block(False), "BucketBlock": {"state": "unknown"}})[0],
            "UNKNOWN",
        )

    def test_failure_retains_unknown_evidence(self):
        a, b = block(False), block(False)
        del a["data"]["IgnorePublicAcls"]
        status, evidence = public_access_block({"AccountBlock": a, "BucketBlock": b})
        self.assertEqual(status, "FAIL")
        self.assertTrue(any("effective=None" in x for x in evidence))

    def test_independent_fields_combined(self):
        a, b = block(False), block(False)
        for i, name in enumerate(BLOCK_FIELDS):
            (a if i % 2 else b)["data"][name] = True
        self.assertEqual(public_access_block({"AccountBlock": a, "BucketBlock": b})[0], "PASS")

    def test_invalid_boolean_remains_unknown(self):
        a = block(False)
        a["data"]["BlockPublicAcls"] = "true"
        b = copy.deepcopy(a)
        for name in BLOCK_FIELDS[1:]:
            a["data"][name] = True
        self.assertEqual(public_access_block({"AccountBlock": a, "BucketBlock": b})[0], "UNKNOWN")

    def test_missing_inputs(self):
        self.assertEqual(public_access_block({})[0], "UNKNOWN")

    def test_versioning_enabled(self):
        self.assertEqual(versioning({"Versioning": present({"Status": "Enabled"})})[0], "PASS")

    def test_versioning_suspended(self):
        self.assertEqual(versioning({"Versioning": present({"Status": "Suspended"})})[0], "FAIL")

    def test_successful_empty_versioning_is_failure(self):
        self.assertEqual(versioning({"Versioning": present({})})[0], "FAIL")

    def test_denied_versioning(self):
        self.assertEqual(versioning({"Versioning": {"state": "unknown"}})[0], "UNKNOWN")

    def test_malformed_versioning(self):
        for value in (None, [], False, 0, "new-state"):
            self.assertEqual(versioning({"Versioning": present({"Status": value})})[0], "UNKNOWN")


class KeyAgeTests(unittest.TestCase):
    def key(self, age, status="Active"):
        return {"Status": status, "CreateDate": NOW - age}

    def test_89_days(self):
        self.assertEqual(key_age(self.key(timedelta(days=89)), NOW, 90)[0], "PASS")

    def test_exactly_90_days(self):
        self.assertEqual(key_age(self.key(timedelta(days=90)), NOW, 90)[0], "PASS")

    def test_90_days_one_second(self):
        self.assertEqual(key_age(self.key(timedelta(days=90, seconds=1)), NOW, 90)[0], "FAIL")

    def test_fractional_boundary(self):
        self.assertEqual(key_age(self.key(timedelta(days=90, microseconds=1)), NOW, 90)[0], "FAIL")

    def test_91_days(self):
        self.assertEqual(key_age(self.key(timedelta(days=91)), NOW, 90)[0], "FAIL")

    def test_inactive_old_key(self):
        self.assertEqual(key_age(self.key(timedelta(days=900), "Inactive"), NOW, 90)[0], "NOT_APPLICABLE")

    def test_expired_key(self):
        self.assertEqual(key_age(self.key(timedelta(days=900), "Expired"), NOW, 90)[0], "NOT_APPLICABLE")

    def test_future_date(self):
        self.assertEqual(key_age(self.key(timedelta(days=-1)), NOW, 90)[0], "UNKNOWN")

    def test_missing_status(self):
        self.assertEqual(key_age({"CreateDate": NOW}, NOW, 90)[0], "UNKNOWN")

    def test_invalid_dates(self):
        for value in (None, "bad", datetime(2025, 1, 1), [], 10):
            self.assertEqual(key_age({"Status": "Active", "CreateDate": value}, NOW, 90)[0], "UNKNOWN")

    def test_timezone_offset(self):
        created = (NOW - timedelta(days=90)).astimezone(timezone(timedelta(hours=5)))
        self.assertEqual(key_age({"Status": "Active", "CreateDate": created.isoformat()}, NOW, 90)[0], "PASS")

    def test_configurable_threshold(self):
        self.assertEqual(key_age(self.key(timedelta(days=31)), NOW, 30)[0], "FAIL")


class MfaTests(unittest.TestCase):
    def user(self, devices=None):
        return {
            "LoginProfile": present({"UserName": "example"}),
            "MFADevices": devices or [],
            "MFAComplete": True,
        }

    def test_console_no_device(self):
        self.assertEqual(console_mfa(self.user())[0], "FAIL")

    def test_console_device(self):
        self.assertEqual(console_mfa(self.user([{"SerialNumber": "example-device"}]))[0], "PASS")

    def test_no_console_fresh_user_exists(self):
        self.assertEqual(
            console_mfa({"LoginProfile": {"state": "absent"}, "UserStillExists": True})[0], "NOT_APPLICABLE"
        )

    def test_no_console_unverified_or_deleted(self):
        for exists in (False, None):
            self.assertEqual(
                console_mfa({"LoginProfile": {"state": "absent"}, "UserStillExists": exists})[0], "UNKNOWN"
            )

    def test_denied_profile(self):
        self.assertEqual(console_mfa({"LoginProfile": {"state": "unknown"}})[0], "UNKNOWN")
        self.assertEqual(console_mfa({"LoginProfile": present({"UserName": ""})})[0], "UNKNOWN")

    def test_denied_device_listing(self):
        user = self.user()
        user["MFAComplete"] = False
        self.assertEqual(console_mfa(user)[0], "UNKNOWN")

    def test_device_on_partial_listing_establishes_registration(self):
        user = self.user([{"SerialNumber": "example-device"}])
        user["MFAComplete"] = False
        self.assertEqual(console_mfa(user)[0], "PASS")

    def test_malformed_device(self):
        self.assertEqual(console_mfa(self.user([{}]))[0], "UNKNOWN")
