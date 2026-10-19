import json, unittest, hashlib, re

def luhn_validate(card_num: str) -> bool:
    digits = [int(c) for c in card_num if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    double = False
    for d in reversed(digits):
        if double:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
        double = not double
    return checksum % 10 == 0

def redact_token(raw: str):
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if len(raw) <= 8:
        redacted = "****"
    else:
        prefix = raw[:4]
        suffix = raw[-4:]
        redacted = f"{prefix}-****-****-{suffix}"
    return redacted, h

class TestDataSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-data-lake.json", "r", encoding="utf-8") as f:
            self.datastores = json.load(f)

    def test_luhn_algorithm_validation(self):
        # Known valid card numbers
        self.assertTrue(luhn_validate("4532015112830366"))
        self.assertTrue(luhn_validate("4532-0151-1283-0366"))
        # Invalid card numbers
        self.assertFalse(luhn_validate("4532015112830367"))
        self.assertFalse(luhn_validate("12345"))

    def test_secret_redaction_and_fingerprinting(self):
        token = "AKIAIOSFODNN7EXAMPLE"
        redacted, fingerprint = redact_token(token)
        self.assertEqual(redacted, "AKIA-****-****-MPLE")
        expected_fp = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.assertEqual(fingerprint, expected_fp)

        short_secret = "secret1"
        red_short, _ = redact_token(short_secret)
        self.assertEqual(red_short, "****")

    def test_inventory_ingestion(self):
        self.assertEqual(len(self.datastores), 6)
        types = {s["store_type"] for s in self.datastores}
        self.assertIn("s3-bucket", types)
        self.assertIn("rds-table", types)
        self.assertIn("gcs-bucket", types)
        self.assertIn("snowflake-warehouse", types)
        self.assertIn("azure-blob", types)
        self.assertIn("bigquery-dataset", types)

    def test_pii_and_pci_detection_in_raw_s3(self):
        s3_store = next(s for s in self.datastores if s["id"] == "ds-s3-001")
        sample_str = json.dumps(s3_store["sample_data"])

        # Check SSN detection
        ssn_matches = re.findall(r'\b\d{3}-\d{2}-\d{4}\b', sample_str)
        self.assertEqual(ssn_matches, ["123-45-6789"])

        # Check Credit Card detection
        cards = [w for w in sample_str.replace('"', ' ').split() if luhn_validate(w)]
        self.assertEqual(cards, ["4532015112830366"])

    def test_ddr_public_exposure_alert(self):
        # A store that is public AND contains sensitive data must trigger DDR-DSPM-001
        exposed_stores = []
        for s in self.datastores:
            sample_str = json.dumps(s.get("sample_data", {}))
            has_pci = any(luhn_validate(w) for w in sample_str.replace('"', ' ').split())
            has_ssn = bool(re.findall(r'\b\d{3}-\d{2}-\d{4}\b', sample_str))
            has_key = "AKIA" in sample_str
            if s.get("is_public") and (has_pci or has_ssn or has_key):
                exposed_stores.append(s["name"])

        self.assertEqual(exposed_stores, ["customer-transactions-raw", "engineering-ci-backups"])

    def test_ddr_unencrypted_shadow_alert(self):
        # A store that is a shadow copy and unencrypted must trigger DDR-DSPM-002
        shadow_unencrypted = [
            s["name"] for s in self.datastores
            if s.get("is_shadow_copy") and not s.get("encryption_enabled")
        ]
        self.assertEqual(shadow_unencrypted, ["user-profiles-shadow-test"])

    def test_evidence_hash_reproducibility(self):
        store = self.datastores[0]
        hash1 = hashlib.sha256(json.dumps(store, sort_keys=True).encode("utf-8")).hexdigest()
        hash2 = hashlib.sha256(json.dumps(store, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

if __name__ == "__main__":
    unittest.main()
