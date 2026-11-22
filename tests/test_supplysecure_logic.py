import json, unittest, hashlib, importlib.machinery, importlib.util

def load_supply_cli():
    loader = importlib.machinery.SourceFileLoader("supplycli", "bin/supplysecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestSupplySecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-slsa-attestation.json", "r", encoding="utf-8") as f:
            self.provenances = json.load(f)
        with open("fixtures/sample-cosign-signatures.json", "r", encoding="utf-8") as f:
            self.signatures = json.load(f)
        with open("fixtures/sample-package-manifest.json", "r", encoding="utf-8") as f:
            self.manifest = json.load(f)
        self.cli = load_supply_cli()

    def test_fixtures_loaded(self):
        self.assertEqual(len(self.provenances), 3)
        self.assertEqual(len(self.signatures), 3)
        self.assertEqual(len(self.manifest), 4)

    def test_slsa_provenance_verification(self):
        all_findings = []
        for prov in self.provenances:
            all_findings.extend(self.cli.evaluate_provenance(prov))

        self.assertEqual(len(all_findings), 3)
        rule_ids = {f["rule_id"] for f in all_findings}
        self.assertEqual(rule_ids, {"SLSA-001", "SLSA-002"})

        # Clean artifact billing-service generates 0 findings
        billing_prov = self.provenances[0]
        self.assertEqual(len(self.cli.evaluate_provenance(billing_prov)), 0)

        # Legacy monolith fails hermetic build (SLSA-001)
        legacy_findings = self.cli.evaluate_provenance(self.provenances[1])
        self.assertEqual(len(legacy_findings), 1)
        self.assertEqual(legacy_findings[0]["rule_id"], "SLSA-001")

        # Analytics worker fails SLSA-001 and mutable tag (SLSA-002)
        worker_findings = self.cli.evaluate_provenance(self.provenances[2])
        self.assertEqual(len(worker_findings), 2)
        worker_rules = {f["rule_id"] for f in worker_findings}
        self.assertEqual(worker_rules, {"SLSA-001", "SLSA-002"})

    def test_cosign_signature_verification(self):
        all_findings = []
        for sig in self.signatures:
            all_findings.extend(self.cli.evaluate_signature(sig))

        self.assertEqual(len(all_findings), 2)

        # Unsigned image creates CRITICAL finding
        unsigned_f = next(f for f in all_findings if f["rule_id"] == "COSIGN-001")
        self.assertEqual(unsigned_f["severity"], "CRITICAL")
        self.assertIn("unverified-sidecar", unsigned_f["resource_id"])

        # Missing Rekor entry creates HIGH finding
        no_rekor_f = next(f for f in all_findings if f["rule_id"] == "COSIGN-002")
        self.assertEqual(no_rekor_f["severity"], "HIGH")
        self.assertIn("shadow-microservice", no_rekor_f["resource_id"])

        # Verified image billing-service creates 0 findings
        verified_sig = self.signatures[0]
        self.assertEqual(len(self.cli.evaluate_signature(verified_sig)), 0)

    def test_dependency_confusion_and_typosquatting(self):
        all_findings = []
        for dep in self.manifest:
            all_findings.extend(self.cli.evaluate_dependency(dep))

        self.assertEqual(len(all_findings), 3)

        # Dependency confusion finding on internal package found on public registry
        conf_f = next(f for f in all_findings if f["rule_id"] == "DEP-CONF-001")
        self.assertEqual(conf_f["severity"], "CRITICAL")
        self.assertEqual(conf_f["resource_id"], "internal-auth-token-signer")

        # Typo-squatting detection
        typo_f = [f for f in all_findings if f["rule_id"] == "TYPO-SQUAT-001"]
        self.assertEqual(len(typo_f), 2)
        targets = {f["title"] for f in typo_f}
        self.assertTrue(any("requests" in t for t in targets))
        self.assertTrue(any("lodash-es" in t for t in targets))

        # Legitimate package react generates 0 findings
        clean_dep = self.manifest[3]
        self.assertEqual(len(self.cli.evaluate_dependency(clean_dep)), 0)

    def test_damerau_levenshtein_distance(self):
        # Substitution
        self.assertEqual(self.cli.damerau_levenshtein_distance("cats", "bats"), 1)
        # Transposition
        self.assertEqual(self.cli.damerau_levenshtein_distance("reqeusts", "requests"), 1)
        # Deletion
        self.assertEqual(self.cli.damerau_levenshtein_distance("lodas-es", "lodash-es"), 1)
        # Identical
        self.assertEqual(self.cli.damerau_levenshtein_distance("react", "react"), 0)

    def test_admission_policy_synthesis(self):
        policy_yaml = self.cli.synthesize_admission_policy()
        self.assertIn("kind: ClusterPolicy", policy_yaml)
        self.assertIn("enforce-cosign-and-slsa-level3", policy_yaml)
        self.assertIn("verify-cosign-signature", policy_yaml)
        self.assertIn("verify-slsa-level3-attestation", policy_yaml)

    def test_ci_cd_workflow_security_scanner(self):
        sample_workflow = """name: CI
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Process Issue Title
        run: echo "Processing ${{ github.event.issue.title }}"
"""
        violations = self.cli.evaluate_workflow(".github/workflows/ci.yml", sample_workflow)
        self.assertEqual(len(violations), 4)

        rule_ids = {v["rule_id"] for v in violations}
        self.assertEqual(rule_ids, {"SUPPLY-CI-001", "SUPPLY-CI-002", "SUPPLY-CI-003", "SUPPLY-CI-004"})

        # Check severity of PwnRequest and Script Injection
        pwn_v = next(v for v in violations if v["rule_id"] == "SUPPLY-CI-002")
        self.assertEqual(pwn_v["severity"], "CRITICAL")

        inj_v = next(v for v in violations if v["rule_id"] == "SUPPLY-CI-003")
        self.assertEqual(inj_v["severity"], "CRITICAL")

    def test_workflow_auto_pinning_patch(self):
        unpinned_workflow = """name: Build
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
"""
        patched = self.cli.generate_pinned_workflow_patch(unpinned_workflow)
        self.assertIn("actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744 # v3.6.0", patched)
        self.assertIn("actions/setup-python@65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236 # v4.7.1", patched)
        self.assertNotIn("actions/checkout@v3\n", patched)

    def test_deterministic_state_hash(self):
        for sig in self.signatures:
            raw = f"{sig['artifact_uri']}:{sig['digest']}:{sig['is_signed']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
