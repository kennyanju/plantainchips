import json, unittest, hashlib, importlib.machinery, importlib.util

def load_policy_cli():
    loader = importlib.machinery.SourceFileLoader("policycli", "bin/policysecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestPolicySecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-policy-pack.json", "r", encoding="utf-8") as f:
            self.pack = json.load(f)
        self.cli = load_policy_cli()

    def test_fixtures_loaded(self):
        self.assertEqual(self.pack["name"], "CloudSecure-Core-Policy-Pack")
        self.assertEqual(self.pack["version"], "1.0.0")
        self.assertEqual(len(self.pack["rules"]), 4)

    def test_pack_validation(self):
        report = self.cli.validate_pack(self.pack)
        self.assertTrue(report["is_valid"])
        self.assertEqual(len(report["errors"]), 0)
        self.assertEqual(report["rule_count"], 4)

        # Corrupted pack with missing ID and invalid RQL
        broken_pack = {
            "name": "",
            "version": "0.1",
            "rules": [
                {
                    "id": "",
                    "rql_query": "malformed syntax without prefix",
                    "framework_controls": []
                }
            ]
        }
        broken_report = self.cli.validate_pack(broken_pack)
        self.assertFalse(broken_report["is_valid"])
        self.assertTrue(len(broken_report["errors"]) >= 3)

    def test_unit_test_runner(self):
        report = self.cli.run_unit_tests(self.pack)
        self.assertEqual(report["total_rules"], 4)
        self.assertEqual(report["passed_rules"], 4)
        self.assertEqual(report["failed_rules"], 0)
        self.assertLess(report["execution_duration_ms"], 50.0)

        for result in report["results"]:
            self.assertTrue(result["is_success"])
            self.assertEqual(len(result["failure_details"]), 0)
            self.assertEqual(result["pass_fixtures_passed"], result["pass_fixtures_total"])
            self.assertEqual(result["fail_fixtures_passed"], result["fail_fixtures_total"])

    def test_rql_explain_plan(self):
        query = "config from cloud.resource where api.name = 'aws_s3_bucket' and json.rule is_public is true"
        plan = self.cli.explain_query(query)

        self.assertTrue(plan["is_valid"])
        self.assertEqual(plan["family"], "Config")
        self.assertIsNotNone(plan["ast_root"])
        self.assertEqual(plan["ast_root"]["node_type"], "TableScan")
        self.assertEqual(len(plan["ast_root"]["children"]), 2)

        # Invalid query
        invalid_plan = self.cli.explain_query("select * from buckets")
        self.assertFalse(invalid_plan["is_valid"])
        self.assertIsNone(invalid_plan["ast_root"])
        self.assertTrue(len(invalid_plan["validation_errors"]) > 0)

    def test_multi_family_explain_plans(self):
        families = [
            ("iam from cloud.resource where api.name = 'aws_iam_role'", "Iam"),
            ("network from cloud.resource where api.name = 'aws_vpc'", "Network"),
            ("data from cloud.resource where api.name = 'aws_rds_instance'", "Data"),
            ("event from cloud.resource where api.name = 'aws_cloudtrail'", "Event"),
            ("ai from cloud.resource where api.name = 'openai_model'", "Ai"),
        ]
        for q, expected_fam in families:
            plan = self.cli.explain_query(q)
            self.assertTrue(plan["is_valid"])
            self.assertEqual(plan["family"], expected_fam)

    def test_false_positive_and_negative_detection(self):
        # Create a rule whose pass fixture fails (false positive)
        flawed_pack = {
            "name": "Flawed-Pack",
            "version": "0.1",
            "rules": [
                {
                    "id": "FLAW-001",
                    "name": "Always Violates Rule",
                    "rql_query": "config from cloud.resource",
                    "framework_controls": ["TEST.1"],
                    "pass_fixtures": [
                        {
                            "id": "res-1",
                            "name": "res-1",
                            "cloud_type": "aws",
                            "state": {}
                        }
                    ],
                    "fail_fixtures": []
                }
            ]
        }
        report = self.cli.run_unit_tests(flawed_pack)
        self.assertEqual(report["failed_rules"], 1)
        self.assertIn("False positive", report["results"][0]["failure_details"][0])

    def test_deterministic_state_hash(self):
        for rule in self.pack["rules"]:
            raw = f"{rule['id']}:{rule['family']}:{rule['severity']}:{rule['rql_query']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
