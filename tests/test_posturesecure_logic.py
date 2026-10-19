import json, unittest, hashlib

class TestPostureSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/aws-cloud-inventory.json", "r", encoding="utf-8") as f:
            self.inventory = json.load(f)

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

if __name__ == "__main__":
    unittest.main()
