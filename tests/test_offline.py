import copy
import json
from pathlib import Path
import tempfile
import unittest

from aws_security_auditor.offline import read_fixture

ROOT = Path(__file__).resolve().parents[1]


class FixtureValidationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "fixtures/demo.json").read_text())

    def read_data(self, data):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            return read_fixture(path)

    def test_missing_scope_is_rejected(self):
        self.data["inventories"].pop()
        with self.assertRaisesRegex(ValueError, "every requested inventory"):
            self.read_data(self.data)

    def test_successful_empty_scope_allowed(self):
        for inv in self.data["inventories"]:
            inv["records"] = []
        scan = self.read_data(self.data)
        self.assertEqual(sum(len(inv.records) for inv in scan.inventories), 0)
        self.assertTrue(all(inv.complete for inv in scan.inventories))

    def test_invalid_envelope_fields(self):
        for name, value in (
            ("schema_version", "2"),
            ("account_id", 1),
            ("account_id", "123"),
            ("regions", []),
            ("regions", ["invalid"]),
            ("regions", ["us-west-2", "us-west-2"]),
            ("inventories", []),
            ("inventories", {}),
        ):
            data = copy.deepcopy(self.data)
            data[name] = value
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValueError):
                    self.read_data(data)

    def test_invalid_inventory_fields(self):
        for name, value in (
            ("kind", "bad"),
            ("region", "global"),
            ("complete", "true"),
            ("records", {}),
            ("errors", {}),
            ("errors", [{}]),
        ):
            data = copy.deepcopy(self.data)
            data["inventories"][0][name] = value
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValueError):
                    self.read_data(data)

    def test_inventory_must_be_object(self):
        self.data["inventories"][0] = None
        with self.assertRaises(ValueError):
            self.read_data(self.data)

    def test_duplicate_inventory_rejected(self):
        self.data["inventories"].append(self.data["inventories"][0])
        with self.assertRaisesRegex(ValueError, "Duplicate inventory"):
            self.read_data(self.data)

    def test_duplicate_resource_identifier_rejected(self):
        self.data["inventories"][0]["records"].append(self.data["inventories"][0]["records"][0])
        with self.assertRaisesRegex(ValueError, "unique nonempty"):
            self.read_data(self.data)

    def test_iam_scope_must_be_global(self):
        self.data["inventories"][-1]["region"] = "us-west-2"
        with self.assertRaises(ValueError):
            self.read_data(self.data)

    def test_error_cannot_be_hidden_by_complete_flag(self):
        inv = self.data["inventories"][0]
        inv["errors"] = [{"operation": "describe_security_groups", "code": "AccessDenied"}]
        scan = self.read_data(self.data)
        self.assertFalse(scan.inventories[0].complete)

    def test_non_json_numbers_and_duplicate_fields_rejected(self):
        for text in ('{"SecurityGroups": NaN}', '{"SecurityGroups": [], "SecurityGroups": []}'):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "bad.json"
                path.write_text(text)
                with self.assertRaises(ValueError):
                    read_fixture(path)

    def test_unknown_configuration_retains_type_for_rule(self):
        self.data["inventories"][2]["records"][0]["Encrypted"] = "false"
        scan = self.read_data(self.data)
        self.assertEqual(scan.inventories[2].records[0]["Encrypted"], "false")
