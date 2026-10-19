import json, unittest, hashlib, importlib.machinery, importlib.util

def load_workload_cli():
    loader = importlib.machinery.SourceFileLoader("workloadcli", "bin/workloadsecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestWorkloadSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-container-image.json", "r", encoding="utf-8") as f:
            self.images = json.load(f)
        with open("fixtures/sample-runtime-events.json", "r", encoding="utf-8") as f:
            self.events = json.load(f)
        self.cli = load_workload_cli()

    def test_image_layers_and_packages_loaded(self):
        self.assertEqual(len(self.images), 1)
        img = self.images[0]
        self.assertEqual(len(img["layers"]), 4)
        layer2 = img["layers"][2]
        self.assertEqual(layer2["packages"][0]["name"], "docker")
        self.assertEqual(layer2["secrets_leaked"], ["AKIAIOSFODNN7EXAMPLE"])

    def test_layer_attributed_cve_scanning(self):
        img = self.images[0]
        vulns = self.cli.scan_image(img)
        self.assertEqual(len(vulns), 3)

        cve_ids = {v["cve_id"] for v in vulns}
        self.assertIn("CVE-2024-41110", cve_ids)
        self.assertIn("CVE-2023-3817", cve_ids)
        self.assertIn("CVE-2023-44487", cve_ids)

        docker_cve = next(v for v in vulns if v["cve_id"] == "CVE-2024-41110")
        self.assertEqual(docker_cve["introduced_in_layer_index"], 2)
        self.assertEqual(docker_cve["severity"], "CRITICAL")
        self.assertEqual(docker_cve["cvss_score"], 10.0)

    def test_runtime_behavioral_anomalies(self):
        anomalies = []
        for ev in self.events:
            anomalies.extend(self.cli.evaluate_runtime_event(ev))

        self.assertEqual(len(anomalies), 4)
        rule_ids = [a["rule_id"] for a in anomalies]
        self.assertIn("CWPP-RT-001", rule_ids)
        self.assertIn("CWPP-RT-002", rule_ids)
        self.assertIn("CWPP-RT-003", rule_ids)

        # Verify clean event 4 (gunicorn) generates no anomalies
        clean_ev = self.events[3]
        clean_anoms = self.cli.evaluate_runtime_event(clean_ev)
        self.assertEqual(len(clean_anoms), 0)

    def test_kubernetes_hardening_synthesis(self):
        yaml_output = self.cli.synthesize_hardening_yaml("ecommerce-frontend")
        self.assertIn("allowPrivilegeEscalation: false", yaml_output)
        self.assertIn("readOnlyRootFilesystem: true", yaml_output)
        self.assertIn("runAsNonRoot: true", yaml_output)
        self.assertIn("type: RuntimeDefault", yaml_output)

    def test_image_state_hash_determinism(self):
        img = self.images[0]
        h1 = hashlib.sha256(json.dumps(img, sort_keys=True).encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(json.dumps(img, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

if __name__ == "__main__":
    unittest.main()
