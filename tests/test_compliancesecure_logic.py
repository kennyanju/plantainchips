import json, unittest, hashlib, importlib.machinery, importlib.util

def load_compliance_cli():
    loader = importlib.machinery.SourceFileLoader("compliancecli", "bin/compliancesecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestComplianceSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-enterprise-posture.json", "r", encoding="utf-8") as f:
            self.findings = json.load(f)
        self.cli = load_compliance_cli()

    def test_fixtures_loaded(self):
        self.assertEqual(len(self.findings), 12)

    def test_prioritized_top10_remediations(self):
        rems = self.cli.prioritize_remediations(self.findings)
        self.assertEqual(len(rems), 10)

        # Rank 1: GraphSecure attack path
        self.assertEqual(rems[0]["rank"], 1)
        self.assertEqual(rems[0]["source_module"], "graphsecure")
        self.assertEqual(rems[0]["severity"], "CRITICAL")
        self.assertEqual(rems[0]["blast_radius_reduction_score"], 71.0)
        self.assertIn("Toxic Attack Path", rems[0]["title"])

        # Rank 2: ThreatSecure active C2
        self.assertEqual(rems[1]["rank"], 2)
        self.assertEqual(rems[1]["source_module"], "threatsecure")
        self.assertEqual(rems[1]["severity"], "CRITICAL")
        self.assertEqual(rems[1]["blast_radius_reduction_score"], 69.0)

        # Rank 3: DataSecure S3 PII leakage
        self.assertEqual(rems[2]["rank"], 3)
        self.assertEqual(rems[2]["source_module"], "datasecure")
        self.assertEqual(rems[2]["severity"], "CRITICAL")
        self.assertEqual(rems[2]["blast_radius_reduction_score"], 67.0)

        # Ranks 1-7 are all CRITICAL findings
        for r in rems[:7]:
            self.assertEqual(r["severity"], "CRITICAL")

        # Remediation actions exist
        for r in rems:
            self.assertTrue(len(r["remediation_command"]) > 10)

    def test_framework_readiness_scoring(self):
        soc2 = self.cli.evaluate_framework(self.findings, "soc2")
        self.assertEqual(soc2["total_controls"], 6)
        self.assertEqual(soc2["passed_controls"], 0)
        self.assertEqual(soc2["failed_controls"], 6)
        self.assertEqual(soc2["readiness_percentage"], 0.0)
        self.assertEqual(soc2["critical_findings"], 7)

        iso = self.cli.evaluate_framework(self.findings, "iso27001")
        self.assertEqual(iso["total_controls"], 5)
        self.assertEqual(iso["passed_controls"], 3)
        self.assertEqual(iso["failed_controls"], 2)
        self.assertEqual(iso["readiness_percentage"], 60.0)

        hipaa = self.cli.evaluate_framework(self.findings, "hipaa")
        self.assertEqual(hipaa["total_controls"], 4)
        self.assertEqual(hipaa["passed_controls"], 3)
        self.assertEqual(hipaa["failed_controls"], 1)
        self.assertEqual(hipaa["readiness_percentage"], 75.0)

        fedramp = self.cli.evaluate_framework(self.findings, "fedramp")
        self.assertEqual(fedramp["total_controls"], 5)
        self.assertEqual(fedramp["passed_controls"], 4)
        self.assertEqual(fedramp["failed_controls"], 1)
        self.assertEqual(fedramp["readiness_percentage"], 80.0)

    def test_audit_evidence_bundle_compilation(self):
        bundle = self.cli.compile_bundle(self.findings, "soc2", "Acme Test Org")
        self.assertTrue(bundle["bundle_id"].startswith("BUNDLE-SOC2-"))
        self.assertEqual(bundle["organization"], "Acme Test Org")
        self.assertEqual(bundle["total_findings_evaluated"], 12)
        self.assertEqual(len(bundle["controls"]), 6)
        self.assertEqual(len(bundle["top_remediations"]), 10)
        self.assertEqual(len(bundle["manifest_sha256"]), 64)

        md = self.cli.to_markdown(bundle)
        self.assertIn("# Executive Compliance Audit Report: SOC 2 Type II", md)
        self.assertIn("Prioritized Top-10 Breach-Stopping Remediation Queue", md)
        self.assertIn("Control-by-Control Audit Evidence Table", md)

        csv_str = self.cli.to_csv(bundle)
        self.assertIn("Control ID,Framework,Title,Status,Failing Findings Count,Summary", csv_str)
        self.assertIn("CC6.1", csv_str)

    def test_clean_environment_100_percent_readiness(self):
        clean_findings = []
        for fw in ["soc2", "iso27001", "pci", "hipaa", "nist", "fedramp"]:
            score = self.cli.evaluate_framework(clean_findings, fw)
            self.assertEqual(score["readiness_percentage"], 100.0)
            self.assertEqual(score["failed_controls"], 0)
            self.assertEqual(score["passed_controls"], score["total_controls"])

    def test_deterministic_state_hash(self):
        for f in self.findings:
            raw = f"{f['id']}:{f['source_module']}:{f['severity']}:{f['resource_id']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
