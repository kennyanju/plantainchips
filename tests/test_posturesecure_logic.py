import json, unittest, hashlib, importlib.machinery, importlib.util

def load_posture_cli():
    loader = importlib.machinery.SourceFileLoader("posturecli", "bin/posturesecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestPostureSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/aws-cloud-inventory.json", "r", encoding="utf-8") as f:
            self.inventory = json.load(f)
        self.cli = load_posture_cli()

    def test_inventory_loaded(self):
        self.assertEqual(len(self.inventory), 6)
        providers = {r["provider"] for r in self.inventory}
        self.assertIn("aws", providers)
        self.assertIn("azure", providers)
        self.assertIn("gcp", providers)

    def test_s3_public_access_block_rule(self):
        # CIS-AWS-3.0-2.1.1: S3 bucket should prohibit public bucket policies
        violating = []
        for r in self.inventory:
            if r["provider"] == "aws" and r["resource_type"] == "aws-s3-bucket":
                pab = r["state"].get("publicAccessBlockConfiguration", {})
                if not pab.get("restrictPublicBuckets", False):
                    violating.append(r["name"])

        self.assertEqual(violating, ["customer-export-bucket"])

    def test_rds_storage_encryption_rule(self):
        # CIS-AWS-3.0-2.2.1: RDS should have storage encryption
        violating = []
        for r in self.inventory:
            if r["provider"] == "aws" and r["resource_type"] == "aws-rds-instance":
                if not r["state"].get("storageEncrypted", False):
                    violating.append(r["name"])

        self.assertEqual(violating, ["legacy-orders"])

    def test_azure_secure_transfer_rule(self):
        # CIS-AZURE-2.1-1: Storage account requires supportsHttpsTrafficOnly
        violating = []
        for r in self.inventory:
            if r["provider"] == "azure" and r["resource_type"] == "azure-storage-account":
                props = r["state"].get("properties", {})
                if not props.get("supportsHttpsTrafficOnly", True):
                    violating.append(r["name"])

        self.assertEqual(violating, ["proddata2026"])

    def test_gcp_uniform_bucket_level_access_rule(self):
        # CIS-GCP-2.0-3.1: Cloud storage requires uniformBucketLevelAccess
        violating = []
        for r in self.inventory:
            if r["provider"] == "gcp" and r["resource_type"] == "gcp-storage-bucket":
                ubla = r["state"].get("uniformBucketLevelAccess", {})
                if not ubla.get("enabled", True):
                    violating.append(r["name"])

        self.assertEqual(violating, ["analytics-exports-gcp"])

    def test_evidence_hash_determinism(self):
        res = self.inventory[0]
        serialized = json.dumps(res["state"], sort_keys=True)
        h1 = hashlib.sha256(serialized.encode()).hexdigest()
        h2 = hashlib.sha256(serialized.encode()).hexdigest()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_multi_cloud_evaluation_and_provider_filter(self):
        all_findings = self.cli.evaluate_inventory(self.inventory)
        self.assertGreaterEqual(len(all_findings), 4)

        aws_findings = self.cli.evaluate_inventory(self.inventory, provider_filter="aws")
        for f in aws_findings:
            self.assertEqual(f["provider"], "aws")

        azure_findings = self.cli.evaluate_inventory(self.inventory, provider_filter="azure")
        for f in azure_findings:
            self.assertEqual(f["provider"], "azure")

    def test_finding_suppression(self):
        findings = self.cli.evaluate_inventory(self.inventory)
        target_fid = findings[0]["id"]

        self.cli.suppress_finding(target_fid, "Approved deviation until Q4")
        # Should be filtered out by default
        active = self.cli.evaluate_inventory(self.inventory, include_suppressed=False)
        self.assertNotIn(target_fid, [f["id"] for f in active])

        # Should appear when include_suppressed=True
        all_incl = self.cli.evaluate_inventory(self.inventory, include_suppressed=True)
        target_f = next(f for f in all_incl if f["id"] == target_fid)
        self.assertEqual(target_f["status"], "SUPPRESSED")
        self.assertEqual(target_f["suppression_reason"], "Approved deviation until Q4")

    def test_rql_query_filtering(self):
        q = "config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket'"
        matched = self.cli.evaluate_rql_query(self.inventory, q)
        self.assertEqual(len(matched), 2)
        for r in matched:
            self.assertEqual(r["provider"], "aws")
            self.assertEqual(r["resource_type"], "aws-s3-bucket")

    def test_drift_detection_attribute_level(self):
        baseline = json.loads(json.dumps(self.inventory))
        current = json.loads(json.dumps(self.inventory))

        # Modify customer-export-bucket in current
        current[0]["state"]["publicAccessBlockConfiguration"]["blockPublicAcls"] = True
        drift = self.cli.detect_drift(baseline, current)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["resource_id"], "res-s3-001")
        self.assertNotEqual(drift[0]["baseline_hash"], drift[0]["current_hash"])
        self.assertGreaterEqual(len(drift[0]["attribute_diffs"]), 1)

    def test_remediation_generation(self):
        findings = self.cli.evaluate_inventory(self.inventory)
        s3_f = next(f for f in findings if f["rule_id"] == "CIS-AWS-3.0-2.1.1")
        self.assertIn("aws_s3_bucket_public_access_block", s3_f["remediation"]["code"])
        self.assertIn("aws s3api put-public-access-block", s3_f["remediation"]["cli_command"])

if __name__ == "__main__":
    unittest.main()
