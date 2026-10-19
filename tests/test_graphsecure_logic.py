import json, unittest, hashlib, importlib.machinery, importlib.util

def load_graph_cli():
    loader = importlib.machinery.SourceFileLoader("graphcli", "bin/graphsecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestGraphSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-attack-graph.json", "r", encoding="utf-8") as f:
            self.graph = json.load(f)
        self.cli = load_graph_cli()

    def test_graph_topology_loaded(self):
        nodes = self.graph["nodes"]
        edges = self.graph["edges"]
        self.assertEqual(len(nodes), 9)
        self.assertEqual(len(edges), 9)

        crown_jewels = [n["id"] for n in nodes if n["is_crown_jewel"]]
        self.assertEqual(sorted(crown_jewels), ["node-customer-pii-s3", "node-prod-aurora-db"])

        exposed = [n["id"] for n in nodes if n["is_internet_exposed"]]
        self.assertIn("node-internet", exposed)
        self.assertIn("node-alb-prod", exposed)
        self.assertIn("node-bastion-vm", exposed)

    def test_attack_path_discovery(self):
        paths = self.cli.find_attack_paths(self.graph)
        self.assertEqual(len(paths), 8)

        # Every path must start at an internet-exposed entry point and end at a crown jewel
        jewel_ids = {"node-customer-pii-s3", "node-prod-aurora-db"}
        for p in paths:
            self.assertTrue(len(p["hops"]) >= 3)
            self.assertIn(p["hops"][-1], jewel_ids)
            self.assertIn(p["hops"][0], ["node-internet", "node-alb-prod", "node-bastion-vm"])

    def test_choke_point_optimization_ranking(self):
        paths = self.cli.find_attack_paths(self.graph)
        choke_points = self.cli.compute_choke_points(self.graph, paths)
        self.assertTrue(len(choke_points) > 0)

        # Top choke point must sever 4 paths with 50.0% ROI
        top_cp = choke_points[0]
        self.assertEqual(top_cp["paths_severed_count"], 4)
        self.assertEqual(top_cp["roi_percentage"], 50.0)

    def test_what_if_remediation_simulation(self):
        initial_paths = self.cli.find_attack_paths(self.graph)
        self.assertEqual(len(initial_paths), 8)

        # Simulate cutting edge-pod-assumes-role
        remaining_edges = [e["id"] for e in self.graph["edges"] if e["id"] != "edge-pod-assumes-role"]
        after_paths = self.cli.find_attack_paths(self.graph, active_edges=remaining_edges)
        self.assertEqual(len(after_paths), 4)

        severed = len(initial_paths) - len(after_paths)
        reduction = (severed / len(initial_paths)) * 100.0
        self.assertEqual(reduction, 50.0)

    def test_graph_state_hash_determinism(self):
        s1 = json.dumps(self.graph, sort_keys=True)
        s2 = json.dumps(self.graph, sort_keys=True)
        h1 = hashlib.sha256(s1.encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(s2.encode("utf-8")).hexdigest()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

if __name__ == "__main__":
    unittest.main()
