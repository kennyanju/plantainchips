import json, unittest, hashlib, importlib.machinery, importlib.util

def load_identity_cli():
    loader = importlib.machinery.SourceFileLoader("identitycli", "bin/identitysecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestIdentitySecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-iam-directory.json", "r", encoding="utf-8") as f:
            self.principals = json.load(f)
        self.cli = load_identity_cli()

    def test_iam_principals_loaded(self):
        self.assertEqual(len(self.principals), 5)
        names = {p["name"] for p in self.principals}
        self.assertIn("CiCdDeploymentAgentRole", names)
        self.assertIn("support_engineer_tier2", names)
        self.assertIn("LegacyNightlyBackupService", names)
        self.assertIn("bi_data_analyst", names)
        self.assertIn("ServerlessCronSchedulerRole", names)

    def test_effective_permissions_calculation(self):
        analyst = next(p for p in self.principals if p["name"] == "bi_data_analyst")
        actions = self.cli.compute_effective_actions(analyst)
        self.assertEqual(actions, ["athena:StartQueryExecution", "s3:GetObject", "s3:ListBucket"])

        admin_role = next(p for p in self.principals if p["name"] == "LegacyNightlyBackupService")
        admin_actions = self.cli.compute_effective_actions(admin_role)
        self.assertIn("*", admin_actions)

    def test_privilege_escalation_detection(self):
        deployer = next(p for p in self.principals if p["name"] == "CiCdDeploymentAgentRole")
        escs = self.cli.find_escalations(deployer)
        vector_ids = [e["vector_id"] for e in escs]
        self.assertIn("CIEM-ESC-001", vector_ids)

        support = next(p for p in self.principals if p["name"] == "support_engineer_tier2")
        support_escs = self.cli.find_escalations(support)
        support_vector_ids = [e["vector_id"] for e in support_escs]
        self.assertIn("CIEM-ESC-002", support_vector_ids)

    def test_entitlement_gap_and_right_sizing(self):
        backup_sa = next(p for p in self.principals if p["name"] == "LegacyNightlyBackupService")
        report = self.cli.right_size_principal(backup_sa)
        self.assertEqual(report["used_actions_count"], 3)
        self.assertEqual(report["granted_actions_count"], 120)
        self.assertEqual(report["entitlement_gap_percentage"], 97.5)
        self.assertIn("dynamodb:GetItem", report["synthesized_least_privilege_policy_json"])

        analyst = next(p for p in self.principals if p["name"] == "bi_data_analyst")
        analyst_report = self.cli.right_size_principal(analyst)
        self.assertEqual(analyst_report["entitlement_gap_percentage"], 0.0)

    def test_state_hash_determinism(self):
        p = self.principals[0]
        h1 = hashlib.sha256(json.dumps(p, sort_keys=True).encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(json.dumps(p, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

if __name__ == "__main__":
    unittest.main()
