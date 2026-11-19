import copy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from aws_security_auditor.__main__ import main
from aws_security_auditor.engine import evaluate
from aws_security_auditor.models import stable_id
from aws_security_auditor.offline import read_fixture
from aws_security_auditor.reporting import build_report, exit_code, markdown, write_reports

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def invoke(self, fixture, *args):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "out"
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "aws_security_auditor",
                "--fixture",
                str(fixture),
                "--output",
                str(self.output),
                *args,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def report(self):
        return json.loads((self.output / "report.json").read_text())

    def test_complete_pass_exit_0(self):
        result = self.invoke(ROOT / "fixtures/pass.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.report()["summary"]["PASS"], 1)

    def test_complete_failure_exit_1(self):
        result = self.invoke(ROOT / "fixtures/fail.json")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.report()["summary"]["FAIL"], 1)

    def test_original_demo_exit_2(self):
        result = self.invoke(ROOT / "fixtures/security_groups.json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.report()["summary"], {"FAIL": 1, "PASS": 1, "UNKNOWN": 1, "NOT_APPLICABLE": 0})
        self.assertEqual(self.report()["scope"]["checks_run"], ["EC2-001"])

    def test_full_demo_counts(self):
        result = self.invoke(ROOT / "fixtures/demo.json")
        self.assertEqual(result.returncode, 2)
        report = self.report()
        self.assertEqual(report["summary"], {"FAIL": 9, "PASS": 8, "UNKNOWN": 7, "NOT_APPLICABLE": 2})
        self.assertEqual(len(report["scope"]["checks_run"]), 7)
        self.assertEqual(report["coverage"]["resource_count"], 19)
        self.assertEqual(report["coverage"]["assessment_count"], 26)

    def test_denied_global_inventory_is_incomplete(self):
        result = self.invoke(ROOT / "fixtures/partial.json")
        self.assertEqual(result.returncode, 2)
        report = self.report()
        self.assertFalse(report["coverage"]["collection_complete"])
        self.assertEqual(report["scan_errors"][0]["code"], "AccessDenied")

    def test_missing_file(self):
        result = self.invoke(ROOT / "fixtures/does-not-exist.json")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder) / "bad.json"
            fixture.write_text("{bad")
            result = self.invoke(fixture)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(self.output.exists())

    def test_invalid_top_level_schema(self):
        for data in (
            [],
            {"SecurityGroups": {}},
            {"SecurityGroups": [None]},
            {"SecurityGroups": [{"IpPermissions": []}]},
            {"SecurityGroups": [{"GroupId": 1}]},
        ):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "bad.json"
                path.write_text(json.dumps(data))
                self.assertEqual(self.invoke(path).returncode, 2)
                self.assertFalse(self.output.exists())

    def test_invalid_cli_flag_combinations(self):
        for args in (
            ("--mode", "live"),
            ("--profile", "test"),
            ("--now", "bad"),
            ("--max-key-age-days", "0"),
            ("--max-key-age-days", "36501"),
        ):
            self.assertEqual(self.invoke(ROOT / "fixtures/pass.json", *args).returncode, 2)

    def test_live_requires_account_and_regions(self):
        for args in (
            ("--mode", "live"),
            ("--mode", "live", "--profile", "lab", "--regions", "us-west-2", "--expected-account", "bad"),
            (
                "--mode",
                "live",
                "--profile",
                "lab",
                "--regions",
                "us-west-2",
                "us-west-2",
                "--expected-account",
                "000000000000",
            ),
        ):
            result = subprocess.run(
                [sys.executable, "-m", "aws_security_auditor", *args],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)

    def test_offline_never_imports_sdk(self):
        with tempfile.TemporaryDirectory() as folder:
            script = "import sys; sys.modules['boto3']=None; sys.modules['botocore']=None; from aws_security_auditor.__main__ import main; raise SystemExit(main())"
            result = subprocess.run(
                [sys.executable, "-c", script, "--fixture", "fixtures/pass.json", "--output", folder],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_output_error_exit_2(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "file"
            path.write_text("occupied")
            with mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(
                    main(["--fixture", str(ROOT / "fixtures/pass.json"), "--output", str(path)]), 2
                )


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.scan = read_fixture(ROOT / "fixtures/demo.json")
        self.now = datetime(2026, 11, 18, 12, tzinfo=timezone.utc)
        self.assessments = evaluate(self.scan, self.now)
        self.report = build_report(self.scan, self.assessments)

    def test_summary_matches_assessments(self):
        for status, count in self.report["summary"].items():
            self.assertEqual(count, sum(a.status == status for a in self.assessments))
        self.assertEqual(sum(self.report["summary"].values()), len(self.assessments))

    def test_findings_derived_from_failures(self):
        self.assertEqual(
            self.report["findings"], [a for a in self.report["assessments"] if a["status"] == "FAIL"]
        )
        for finding in self.report["findings"]:
            self.assertTrue(finding["evidence"])
            self.assertTrue(finding["recommendation"])
            self.assertTrue(finding["risk"])
            self.assertTrue(finding["verification"])

    def test_severity_counts_only_failures(self):
        self.assertEqual(self.report["failed_by_severity"], {"HIGH": 3, "MEDIUM": 4, "LOW": 2})

    def test_ids_stable_across_collection_times(self):
        changed = copy.deepcopy(self.scan)
        for inv in changed.inventories:
            inv.collected_at = "2026-11-19T12:00:00+00:00"
        self.assertEqual([a.id for a in self.assessments], [a.id for a in evaluate(changed, self.now)])

    def test_reordered_input_preserves_result_order(self):
        changed = copy.deepcopy(self.scan)
        changed.inventories.reverse()
        for inv in changed.inventories:
            inv.records.reverse()
        self.assertEqual(self.assessments, evaluate(changed, self.now))

    def test_key_identifiers_masked_and_ids_distinct(self):
        inv = self.scan.inventories[-1]
        user = inv.records[0]
        other = copy.deepcopy(user["AccessKeys"][0])
        other["AccessKeyId"] = "DIFFERENT-KEY-SAME0001"
        user["AccessKeys"].append(other)
        keys = [
            a
            for a in evaluate(self.scan, self.now)
            if a.check_id == "IAM-001" and a.resource_type == "AWS::IAM::AccessKey"
        ]
        self.assertEqual(len({a.id for a in keys}), len(keys))
        self.assertNotIn("EXAMPLE-KEY", json.dumps(build_report(self.scan, evaluate(self.scan, self.now))))

    def test_no_keys_does_not_invent_key_assessment(self):
        arn = "arn:aws:iam::000000000000:user/example-api-user"
        self.assertEqual(
            [a for a in self.assessments if a.resource_id == arn and a.check_id == "IAM-001"], []
        )

    def test_bad_key_id_is_unknown(self):
        self.scan.inventories[-1].records[0]["AccessKeys"] = [{}]
        results = evaluate(self.scan, self.now)
        self.assertTrue(any(a.check_id == "IAM-001" and a.status == "UNKNOWN" for a in results))

    def test_incompleteness_has_exit_priority(self):
        self.assertEqual(exit_code(self.report), 2)
        self.assertGreater(self.report["summary"]["FAIL"], 0)

    def test_failed_group_with_missing_rule_keeps_scan_incomplete(self):
        scan = read_fixture(ROOT / "fixtures/fail.json")
        scan.inventories[0].records[0]["IpPermissions"].append({})
        report = build_report(scan, evaluate(scan, self.now))
        self.assertEqual(report["summary"]["FAIL"], 1)
        self.assertEqual(report["summary"]["UNKNOWN"], 0)
        self.assertEqual(exit_code(report), 2)

    def test_failed_bucket_with_unknown_effective_field_keeps_scan_incomplete(self):
        scan = copy.deepcopy(self.scan)
        for inv in scan.inventories:
            inv.records = []
        scan.inventories[3].records = [
            {
                "Name": "example-mixed",
                "AccountBlock": {"state": "present", "data": {"BlockPublicAcls": False}},
                "BucketBlock": {"state": "present", "data": {"BlockPublicAcls": False}},
                "Versioning": {"state": "present", "data": {"Status": "Enabled"}},
            }
        ]
        report = build_report(scan, evaluate(scan, self.now))
        self.assertEqual(report["summary"]["FAIL"], 1)
        self.assertEqual(report["summary"]["UNKNOWN"], 0)
        self.assertEqual(exit_code(report), 2)

    def test_reports_are_written_and_marked_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            write_reports(self.report, Path(folder))
            self.assertEqual(json.loads((Path(folder) / "report.json").read_text()), self.report)
            text = (Path(folder) / "report.md").read_text()
            self.assertIn("OFFLINE", text)
            self.assertIn("Invented local fixtures", text)
            self.assertIn("UNKNOWN assessments", text)

    def test_markdown_escapes_resource_content(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["resource_id"] = "<script>\n|bad|"
        text = markdown(report)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("\\|bad\\|", text)

    def test_stable_id_scope_separation(self):
        first = stable_id("000000000000", "us-west-2", "sg-example", "EC2-001")
        self.assertNotEqual(first, stable_id("000000000000", "us-east-1", "sg-example", "EC2-001"))
        self.assertNotEqual(first, stable_id("111111111111", "us-west-2", "sg-example", "EC2-001"))
