import json, unittest, hashlib, importlib.machinery, importlib.util

def load_code_cli():
    loader = importlib.machinery.SourceFileLoader("codecli", "bin/codesecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestCodeSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-iac-bundle.json", "r", encoding="utf-8") as f:
            self.iac_files = json.load(f)
        with open("fixtures/sample-sbom-components.json", "r", encoding="utf-8") as f:
            self.components = json.load(f)
        self.cli = load_code_cli()

    def test_iac_multi_format_scanning(self):
        self.assertEqual(len(self.iac_files), 6)
        all_findings = []
        for file_obj in self.iac_files:
            all_findings.extend(self.cli.scan_file(file_obj))

        self.assertEqual(len(all_findings), 8)
        rule_ids = {f["rule_id"] for f in all_findings}
        expected_rules = {
            "IAC_AWS_001",
            "IAC_AWS_002",
            "IAC_SEC_001",
            "IAC_K8S_001",
            "IAC_K8S_002",
            "IAC_DOCKER_001",
            "IAC_DOCKER_002",
            "IAC_GHA_001",
        }
        self.assertEqual(rule_ids, expected_rules)

        # Verify critical severities
        criticals = [f for f in all_findings if f["severity"] == "CRITICAL"]
        self.assertEqual(len(criticals), 4)

    def test_automated_fix_patch_generation(self):
        s3_file = next(f for f in self.iac_files if f["path"] == "terraform/storage.tf")
        s3_findings = self.cli.scan_file(s3_file)
        self.assertEqual(len(s3_findings), 1)
        self.assertIn("acl    = \"private\"", s3_findings[0]["auto_fix_patch"])

        k8s_file = next(f for f in self.iac_files if f["path"] == "k8s/deployment.yaml")
        k8s_findings = self.cli.scan_file(k8s_file)
        priv_finding = next(f for f in k8s_findings if f["rule_id"] == "IAC_K8S_001")
        self.assertIn("privileged: false", priv_finding["auto_fix_patch"])

        docker_file = next(f for f in self.iac_files if f["path"] == "docker/Dockerfile")
        docker_findings = self.cli.scan_file(docker_file)
        user_finding = next(f for f in docker_findings if f["rule_id"] == "IAC_DOCKER_001")
        self.assertEqual(user_finding["auto_fix_patch"], "USER 10001:10001")

    def test_cyclonedx_sbom_generation(self):
        sbom = self.cli.generate_cyclonedx_sbom(self.components)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(len(sbom["components"]), 3)
        self.assertEqual(sbom["components"][0]["name"], "tokio")
        self.assertEqual(sbom["components"][0]["licenses"][0]["license"]["id"], "MIT")

    def test_deterministic_source_hash(self):
        for f in self.iac_files:
            digest = hashlib.sha256(f["content"].encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
