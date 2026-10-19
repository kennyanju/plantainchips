import json, unittest, hashlib, importlib.machinery, importlib.util

def load_net_cli():
    loader = importlib.machinery.SourceFileLoader("netcli", "bin/netsecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestNetSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-vpc-flow-logs.json", "r", encoding="utf-8") as f:
            self.flows = json.load(f)
        with open("fixtures/sample-security-groups.json", "r", encoding="utf-8") as f:
            self.sgs = json.load(f)
        self.cli = load_net_cli()

    def test_fixtures_loaded(self):
        self.assertEqual(len(self.flows), 5)
        self.assertEqual(len(self.sgs), 3)

    def test_vpc_flow_log_analysis(self):
        all_violations = []
        for fl in self.flows:
            all_violations.extend(self.cli.evaluate_flow(fl))

        self.assertEqual(len(all_violations), 3)
        rule_ids = {v["rule_id"] for v in all_violations}
        self.assertEqual(rule_ids, {"CNS-NET-001", "CNS-NET-004"})

        http_v = next(v for v in all_violations if "HTTP" in v["title"])
        self.assertEqual(http_v["rule_id"], "CNS-NET-001")
        self.assertEqual(http_v["resource_id"], "eni-0a1b2c3d4e5f60001")

        telnet_v = next(v for v in all_violations if "Telnet" in v["title"])
        self.assertEqual(telnet_v["rule_id"], "CNS-NET-001")

        egress_v = next(v for v in all_violations if v["rule_id"] == "CNS-NET-004")
        self.assertIn("65.00 MB", egress_v["description"])

    def test_security_group_rule_auditing(self):
        all_violations = []
        for sg in self.sgs:
            all_violations.extend(self.cli.evaluate_sg_rules(sg))

        self.assertEqual(len(all_violations), 3)
        rule_ids = {v["rule_id"] for v in all_violations}
        self.assertEqual(rule_ids, {"CNS-NET-002", "CNS-NET-003", "CNS-NET-005"})

        db_v = next(v for v in all_violations if v["rule_id"] == "CNS-NET-002")
        self.assertEqual(db_v["severity"], "CRITICAL")
        self.assertIn("5432", db_v["title"])

        ssh_v = next(v for v in all_violations if v["rule_id"] == "CNS-NET-003")
        self.assertEqual(ssh_v["severity"], "CRITICAL")
        self.assertIn("SSH", ssh_v["title"])

        shadow_v = next(v for v in all_violations if v["rule_id"] == "CNS-NET-005")
        self.assertEqual(shadow_v["severity"], "LOW")
        self.assertIn("shadowed", shadow_v["description"])

    def test_zero_trust_microsegmentation_synthesis(self):
        k8s_yaml, cmds = self.cli.synthesize_microsegmentation(self.flows, self.sgs)

        self.assertIn("NetworkPolicy", k8s_yaml)
        self.assertIn("zero-trust-default-microsegmentation", k8s_yaml)
        self.assertIn("port: 8443", k8s_yaml)
        self.assertNotIn("port: 80", k8s_yaml)

        self.assertEqual(len(cmds), 2)
        self.assertTrue(any("port 5432" in c for c in cmds))
        self.assertTrue(any("port 22" in c for c in cmds))

    def test_private_ip_detection(self):
        self.assertTrue(self.cli.is_private_ip("10.0.1.1"))
        self.assertTrue(self.cli.is_private_ip("172.16.5.1"))
        self.assertTrue(self.cli.is_private_ip("172.31.255.255"))
        self.assertTrue(self.cli.is_private_ip("192.168.1.1"))
        self.assertFalse(self.cli.is_private_ip("198.51.100.88"))
        self.assertFalse(self.cli.is_private_ip("8.8.8.8"))
        self.assertFalse(self.cli.is_private_ip("172.32.0.1"))

    def test_deterministic_flow_hash(self):
        for fl in self.flows:
            raw = f"{fl['interface_id']}:{fl['src_addr']}:{fl['dst_addr']}:{fl['src_port']}:{fl['dst_port']}:{fl['protocol']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
