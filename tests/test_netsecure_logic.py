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

    def test_bitwise_cidr_and_reachability(self):
        # Bitwise CIDR containment
        self.assertTrue(self.cli.cidr_contains_ip("10.0.0.0/16", "10.0.1.5"))
        self.assertTrue(self.cli.cidr_contains_ip("10.0.0.0/16", "10.0.254.254"))
        self.assertFalse(self.cli.cidr_contains_ip("10.0.0.0/16", "10.1.0.1"))
        self.assertTrue(self.cli.cidr_contains_ip("0.0.0.0/0", "198.51.100.2"))
        self.assertTrue(self.cli.cidr_contains_ip("192.168.1.0/24", "192.168.1.254"))
        self.assertFalse(self.cli.cidr_contains_ip("192.168.1.0/24", "192.168.2.1"))

        # Symbolic reachability solver across security groups
        # 1. Public SSH access (port 22) from arbitrary public IP
        perm_ssh, rules_ssh = self.cli.check_reachability(self.sgs, "203.0.113.5", 22, "tcp")
        self.assertTrue(perm_ssh)
        self.assertEqual(len(rules_ssh), 1)
        self.assertEqual(rules_ssh[0]["rule_id"], "sgr-002")

        # 2. Public DB access (port 5432) from arbitrary public IP
        perm_db, rules_db = self.cli.check_reachability(self.sgs, "198.51.100.88", 5432, "tcp")
        self.assertTrue(perm_db)
        self.assertEqual(len(rules_db), 1)
        self.assertEqual(rules_db[0]["rule_id"], "sgr-001")

        # 3. Microservice RPC (port 8443) allowed for 10.0.0.0/16
        perm_rpc, rules_rpc = self.cli.check_reachability(self.sgs, "10.0.1.5", 8443, "tcp")
        self.assertTrue(perm_rpc)
        self.assertEqual(len(rules_rpc), 1)

        # 4. Microservice RPC blocked for IP outside 10.0.0.0/16 (e.g. 10.1.5.5)
        perm_rpc_block, rules_rpc_block = self.cli.check_reachability(self.sgs, "10.1.5.5", 8443, "tcp")
        self.assertFalse(perm_rpc_block)
        self.assertEqual(len(rules_rpc_block), 0)

        # 5. Port with no ingress rule (e.g. 3389)
        perm_rdp, _ = self.cli.check_reachability(self.sgs, "10.0.1.5", 3389, "tcp")
        self.assertFalse(perm_rdp)

    def test_east_west_traffic_matrix(self):
        matrix = self.cli.compute_traffic_matrix(self.flows, self.sgs)
        self.assertEqual(len(matrix), 5)

        # Verify cleartext HTTP flow status
        http_m = next(m for m in matrix if m["port"] == 80)
        self.assertEqual(http_m["status"], "VIOLATION")

        # Verify exfiltration flow status
        exfil_m = next(m for m in matrix if m["destination"] == "198.51.100.88")
        self.assertEqual(exfil_m["status"], "VIOLATION")
        self.assertEqual(exfil_m["bytes"], 65000000)

        # Verify legitimate microservice flow
        rpc_m = next(m for m in matrix if m["port"] == 8443)
        self.assertEqual(rpc_m["status"], "PERMITTED")
        self.assertTrue(rpc_m["permitted_by_sg"])

        # Verify blocked flow
        reject_m = next(m for m in matrix if m["port"] == 445)
        self.assertEqual(reject_m["status"], "DENIED")

    def test_deterministic_flow_hash(self):
        for fl in self.flows:
            raw = f"{fl['interface_id']}:{fl['src_addr']}:{fl['dst_addr']}:{fl['src_port']}:{fl['dst_port']}:{fl['protocol']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
