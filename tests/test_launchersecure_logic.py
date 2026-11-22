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

    def test_catalog_sort_functions(self):
        catalog = self.cli.CATALOG
        sorted_by_name = self.cli.sort_catalog(catalog, sort_by="name")
        self.assertEqual(sorted_by_name[0]["name"], "AiSecure")
        self.assertEqual(sorted_by_name[-1]["name"], "WorkloadSecure")

        sorted_by_size_desc = self.cli.sort_catalog(catalog, sort_by="size", sort_desc=True)
        self.assertGreaterEqual(sorted_by_size_desc[0]["download_size_mb"], sorted_by_size_desc[-1]["download_size_mb"])

    def test_stream_hash_quarantine_on_mismatch(self):
        corrupted_payload = b"corrupted-binary-payload"
        expected_digest = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        res = self.cli.install_or_update_app("workloadsecure", "0.2.0", corrupted_payload, expected_digest)
        self.assertEqual(res["status"], "quarantined")
        self.assertEqual(res["app_id"], "workloadsecure")
        self.assertIn("quarantined", res["error"].lower())

        target = next(a for a in self.cli.CATALOG if a["id"] == "workloadsecure")
        self.assertEqual(target["status"], "QUARANTINED")

    def test_update_all_and_rollback_store(self):
        # Set workloadsecure to update available
        target = next(a for a in self.cli.CATALOG if a["id"] == "workloadsecure")
        target["installed_version"] = "0.0.9"
        target["status"] = "UPDATE_AVAILABLE"

        res = self.cli.update_all_apps()
        self.assertGreaterEqual(res["total_updated"], 1)
        self.assertEqual(target["installed_version"], target["latest_version"])
        self.assertEqual(target["status"], "INSTALLED")

        # Rollback should now revert to 0.0.9
        rb = self.cli.rollback_app_version("workloadsecure")
        self.assertEqual(rb["status"], "rolled_back")
        self.assertEqual(rb["restored_version"], "0.0.9")
        self.assertEqual(target["installed_version"], "0.0.9")

    def test_resolve_platform_package(self):
        pkg = self.cli.resolve_platform_package(self.manifest, "macos-aarch64")
        self.assertIsNotNone(pkg)
        self.assertEqual(pkg["platform"], "macos-aarch64")
        self.assertEqual(pkg["format"], "dmg")
        self.assertTrue(pkg["filename"].endswith(".dmg"))

        pkg_wasm = self.cli.resolve_platform_package(self.manifest, "wasm32")
        self.assertIsNotNone(pkg_wasm)
        self.assertEqual(pkg_wasm["format"], "wasm")

    def test_posture_pulse_summary(self):
        pulse = self.cli.get_posture_pulse()
        self.assertIn("total_findings", pulse)
        self.assertIn("by_severity", pulse)
        self.assertIn("apps_pulse", pulse)
        self.assertEqual(len(pulse["apps_pulse"]), 14)

        # Ensure workbench routes exist for all apps
        for a in pulse["apps_pulse"]:
            self.assertTrue(a["workbench_route"].startswith("web/workbench.html?app="))

if __name__ == "__main__":
    unittest.main()
