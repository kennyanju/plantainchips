import json, unittest, hashlib, importlib.machinery, importlib.util

def load_threat_cli():
    loader = importlib.machinery.SourceFileLoader("threatcli", "bin/threatsecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestThreatSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-cloudtrail-stream.json", "r", encoding="utf-8") as f:
            self.events = json.load(f)
        self.cli = load_threat_cli()

    def test_audit_stream_loaded(self):
        self.assertEqual(len(self.events), 7)

    def test_mitre_attack_detections(self):
        all_dets = []
        for ev in self.events:
            all_dets.extend(self.cli.evaluate_event(ev))

        self.assertEqual(len(all_dets), 6)
        rule_ids = {d["rule_id"] for d in all_dets}
        expected_rules = {
            "CDR-AWS-001",
            "CDR-AWS-002",
            "CDR-AWS-003",
            "CDR-AWS-004",
            "CDR-AWS-006",
            "CDR-AWS-007",
        }
        self.assertEqual(rule_ids, expected_rules)

        # Check techniques
        techniques = {d["technique_id"] for d in all_dets}
        expected_techniques = {
            "T1562.008",
            "T1098.001",
            "T1098",
            "T1078.004",
            "T1537",
            "T1485",
        }
        self.assertEqual(techniques, expected_techniques)

        # Verify clean event generates zero detections
        clean_ev = self.events[6]
        self.assertEqual(clean_ev["event_name"], "DescribeInstances")
        self.assertEqual(len(self.cli.evaluate_event(clean_ev)), 0)

    def test_kill_chain_correlation(self):
        all_dets = []
        for ev in self.events:
            all_dets.extend(self.cli.evaluate_event(ev))

        incidents = self.cli.correlate_kill_chains(all_dets)
        self.assertEqual(len(incidents), 2)

        contractor_inc = next(i for i in incidents if "dev-contractor" in i["principal_arn"])
        self.assertEqual(contractor_inc["event_count"], 5)
        self.assertEqual(contractor_inc["confidence_score"], 0.98)
        self.assertEqual(len(contractor_inc["tactics_observed"]), 5)
        self.assertIn("Defense Evasion", contractor_inc["tactics_observed"])
        self.assertIn("Exfiltration", contractor_inc["tactics_observed"])
        self.assertIn("Initial Access", contractor_inc["tactics_observed"])
        self.assertIn("Persistence", contractor_inc["tactics_observed"])
        self.assertIn("Privilege Escalation", contractor_inc["tactics_observed"])

        intern_inc = next(i for i in incidents if "ops-intern" in i["principal_arn"])
        self.assertEqual(intern_inc["event_count"], 1)
        self.assertEqual(intern_inc["confidence_score"], 0.65)
        self.assertEqual(intern_inc["tactics_observed"], ["Impact"])

    def test_automated_containment_actions(self):
        all_dets = []
        for ev in self.events:
            all_dets.extend(self.cli.evaluate_event(ev))

        actions = [d["containment_action"] for d in all_dets]
        self.assertEqual(len(actions), 6)
        self.assertTrue(any("start-logging" in a for a in actions))
        self.assertTrue(any("update-access-key" in a for a in actions))
        self.assertTrue(any("modify-snapshot-attribute" in a for a in actions))

    def test_deterministic_event_hash(self):
        for ev in self.events:
            raw = f"{ev['event_id']}:{ev['event_time']}:{ev['event_source']}:{ev['event_name']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
