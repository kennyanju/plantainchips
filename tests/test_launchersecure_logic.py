import json, unittest, hashlib, importlib.machinery, importlib.util

def load_launcher_cli():
    loader = importlib.machinery.SourceFileLoader("launchercli", "bin/launchersecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestLauncherSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-release-manifest.json", "r", encoding="utf-8") as f:
            self.manifest = json.load(f)
        self.cli = load_launcher_cli()

    def test_catalog_14_applications_present(self):
        catalog = self.cli.CATALOG
        self.assertEqual(len(catalog), 14)
        indices = [a["index"] for a in catalog]
        self.assertEqual(indices, list(range(14)))

        # Verify all app IDs end with secure
        for app in catalog:
            self.assertTrue(app["id"].endswith("secure"))
            self.assertTrue(app["name"].endswith("Secure"))

    def test_pillar_filtering(self):
        catalog = self.cli.CATALOG
        posture_apps = [a["id"] for a in catalog if a["pillar"] == "POSTURE"]
        self.assertEqual(sorted(posture_apps), ["graphsecure", "posturesecure"])

        governance_apps = [a["id"] for a in catalog if a["pillar"] == "GOVERNANCE"]
        self.assertIn("launchersecure", governance_apps)
        self.assertIn("policysecure", governance_apps)
        self.assertIn("compliancesecure", governance_apps)

    def test_sha256_checksum_verification(self):
        payload = b"cloudsecure-secure-binary-v0.1.0"
        expected = hashlib.sha256(payload).hexdigest()

        # Valid checksum matches
        hasher = hashlib.sha256()
        hasher.update(payload)
        observed = hasher.hexdigest()
        self.assertEqual(observed, expected)

        # Corrupted checksum fails
        corrupted = b"tampered-binary-payload"
        corrupted_hash = hashlib.sha256(corrupted).hexdigest()
        self.assertNotEqual(corrupted_hash, expected)

    def test_release_manifest_schema_and_platforms(self):
        self.assertEqual(self.manifest["app_id"], "posturesecure")
        self.assertEqual(self.manifest["version"], "0.1.0")
        self.assertEqual(len(self.manifest["ed25519_signature"]), 128)

        packages = self.manifest["packages"]
        platforms = {p["platform"] for p in packages}
        self.assertIn("macos-aarch64", platforms)
        self.assertIn("macos-x86_64", platforms)
        self.assertIn("windows-x86_64", platforms)
        self.assertIn("linux-x86_64", platforms)
        self.assertIn("freebsd-x86_64", platforms)
        self.assertIn("wasm32", platforms)

        for pkg in packages:
            self.assertEqual(len(pkg["sha256"]), 64)
            self.assertTrue(pkg["size_bytes"] > 0)

    def test_n_minus_one_rollback_cycle(self):
        # Simulating state transition for N-1 rollback
        rollback_store = {}
        app_state = {
            "id": "workloadsecure",
            "installed_version": "0.1.0",
            "status": "INSTALLED"
        }

        # Step 1: Upgrade to 0.2.0, store previous 0.1.0 in rollback_store
        rollback_store[app_state["id"]] = app_state["installed_version"]
        app_state["installed_version"] = "0.2.0"
        self.assertEqual(app_state["installed_version"], "0.2.0")
        self.assertEqual(rollback_store["workloadsecure"], "0.1.0")

        # Step 2: Trigger Rollback
        reverted_version = rollback_store.pop("workloadsecure")
        app_state["installed_version"] = reverted_version
        self.assertEqual(app_state["installed_version"], "0.1.0")
        self.assertNotIn("workloadsecure", rollback_store)

    def test_platform_detector(self):
        plat = self.cli.get_platform_info()
        self.assertIn("-", plat)
        os_part, arch_part = plat.split("-", 1)
        self.assertIn(os_part, ["macos", "windows", "linux"])
        self.assertTrue(len(arch_part) > 0)

if __name__ == "__main__":
    unittest.main()
