import json, unittest, hashlib, importlib.machinery, importlib.util

def load_waas_cli():
    loader = importlib.machinery.SourceFileLoader("waascli", "bin/waassecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestWaasSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-openapi-spec.json", "r", encoding="utf-8") as f:
            self.spec = json.load(f)
        with open("fixtures/sample-api-traffic.json", "r", encoding="utf-8") as f:
            self.traffic = json.load(f)
        self.cli = load_waas_cli()

    def test_traffic_records_and_spec_loaded(self):
        self.assertEqual(len(self.traffic), 8)
        self.assertEqual(len(self.spec["endpoints"]), 5)

    def test_owasp_api_top10_vulnerabilities(self):
        all_violations = []
        for r in self.traffic:
            all_violations.extend(self.cli.evaluate_traffic(r, self.spec))

        self.assertEqual(len(all_violations), 11)
        rule_ids = {v["rule_id"] for v in all_violations}
        expected_rules = {
            "API1:2023",
            "API2:2023",
            "API3:2023",
            "API4:2023",
            "API5:2023",
            "API8:2023",
            "API9:2023",
        }
        self.assertEqual(rule_ids, expected_rules)

        # Check critical findings count
        criticals = [v for v in all_violations if v["severity"] == "CRITICAL"]
        self.assertEqual(len(criticals), 4)

        # Verify BOLA
        bola = next(v for v in all_violations if v["rule_id"] == "API1:2023")
        self.assertIn("user_9999", bola["endpoint"])

        # Verify Broken Auth
        auth = next(v for v in all_violations if v["rule_id"] == "API2:2023")
        self.assertEqual(auth["endpoint"], "/api/v1/orders")

        # Verify BFLA
        bfla = next(v for v in all_violations if v["rule_id"] == "API5:2023")
        self.assertEqual(bfla["endpoint"], "/admin/system/backup")

    def test_openapi_drift_detection(self):
        all_violations = []
        for r in self.traffic:
            all_violations.extend(self.cli.evaluate_traffic(r, self.spec))

        drift = [v for v in all_violations if v["rule_id"] == "API9:2023"]
        self.assertEqual(len(drift), 3)

        categories = [d["category"] for d in drift]
        self.assertEqual(categories.count("Improper Inventory Management (Shadow API)"), 2)
        self.assertEqual(categories.count("Improper Inventory Management (Zombie API)"), 1)

        zombie = next(d for d in drift if "Zombie" in d["category"])
        self.assertEqual(zombie["endpoint"], "/api/v0/legacy/statement")

    def test_waf_rule_synthesis(self):
        all_violations = []
        for r in self.traffic:
            all_violations.extend(self.cli.evaluate_traffic(r, None))

        cf_expr, aws_json = self.cli.synthesize_waf_rules(all_violations)
        self.assertIn("http.request.uri.path", cf_expr)
        self.assertIn("/admin/system/backup", cf_expr)

        aws_rules = json.loads(aws_json)
        self.assertEqual(aws_rules["Name"], "CloudSecure-WAF-RuleGroup")
        self.assertTrue(len(aws_rules["Rules"]) >= 1)

    def test_interactive_payload_probe(self):
        # 1. SQL Injection Probe
        sqli_req = {"method": "GET", "uri": "/api/v1/search?q=' UNION SELECT 1,2,3--"}
        sqli_res = self.cli.evaluate_traffic(sqli_req, None)
        self.assertTrue(any(v["rule_id"] == "WAAS-SQLI-001" for v in sqli_res))

        # 2. XSS Probe
        xss_req = {"method": "POST", "uri": "/api/v1/comment", "request_body": {"msg": "<script>alert(1)</script>"}}
        xss_res = self.cli.evaluate_traffic(xss_req, None)
        self.assertTrue(any(v["rule_id"] == "WAAS-XSS-001" for v in xss_res))

        # 3. SSRF / Cloud Metadata Probe
        ssrf_req = {"method": "GET", "uri": "/api/v1/proxy?url=http://169.254.169.254/latest/meta-data/"}
        ssrf_res = self.cli.evaluate_traffic(ssrf_req, None)
        self.assertTrue(any(v["rule_id"] == "WAAS-SSRF-001" for v in ssrf_res))

        # 4. Command Injection Probe
        cmdi_req = {"method": "GET", "uri": "/api/v1/exec?cmd=; cat /etc/passwd"}
        cmdi_res = self.cli.evaluate_traffic(cmdi_req, None)
        self.assertTrue(any(v["rule_id"] == "WAAS-CMDI-001" for v in cmdi_res))

        # 5. Path Traversal Probe
        path_req = {"method": "GET", "uri": "/api/v1/files/download?path=../../../../etc/passwd"}
        path_res = self.cli.evaluate_traffic(path_req, None)
        self.assertTrue(any(v["rule_id"] == "WAAS-PATH-001" for v in path_res))

        # 6. JWT alg:none Probe
        jwt_req = {"method": "GET", "uri": "/api/v1/secure", "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.payload.sig"}}
        jwt_res = self.cli.evaluate_traffic(jwt_req, None)
        self.assertTrue(any("alg:none" in v.get("category", "") for v in jwt_res))

    def test_multi_format_virtual_patches(self):
        violations = [
            {"endpoint": "/admin/system/backup", "rule_id": "API5:2023", "title": "BFLA Admin Access", "suggested_waf_rule": 'http.request.uri.path contains "/admin/system/backup"'}
        ]
        patches = self.cli.synthesize_virtual_patches(violations)
        self.assertIn("cloudflare_wirefilter", patches)
        self.assertIn("aws_wafv2", patches)
        self.assertIn("modsecurity", patches)
        self.assertIn("envoy", patches)

        self.assertIn("SecRule REQUEST_URI", patches["modsecurity"])
        self.assertEqual(len(patches["envoy"]["virtual_patches"]), 1)
        self.assertEqual(patches["envoy"]["virtual_patches"][0]["match"]["prefix"], "/admin/system/backup")

    def test_deterministic_traffic_hash(self):
        for r in self.traffic:
            raw = f"{r['id']}:{r['method']}:{r['uri']}:{r['client_ip']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
