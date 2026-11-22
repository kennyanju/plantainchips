import json
import os
import subprocess
import sys
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN_DIR = os.path.join(PROJECT_ROOT, "bin")
FIXTURES_DIR = os.path.join(PROJECT_ROOT, "fixtures")

ALL_CLIS = [
    "aisecure-cli",
    "codesecure-cli",
    "compliancesecure-cli",
    "datasecure-cli",
    "graphsecure-cli",
    "identitysecure-cli",
    "launchersecure-cli",
    "netsecure-cli",
    "policysecure-cli",
    "posturesecure-cli",
    "supplysecure-cli",
    "threatsecure-cli",
    "waassecure-cli",
    "workloadsecure-cli",
]

SARIF_COMMANDS = {
    "aisecure-cli": ["audit-posture", "-i", os.path.join(FIXTURES_DIR, "sample-ai-inventory.json"), "-o", "sarif"],
    "codesecure-cli": ["scan", "-i", os.path.join(FIXTURES_DIR, "sample-iac-bundle.json"), "-f", "sarif"],
    "compliancesecure-cli": ["aggregate", "-s", os.path.join(FIXTURES_DIR, "sample-enterprise-posture.json"), "-o", "sarif"],
    "datasecure-cli": ["scan", "-i", os.path.join(FIXTURES_DIR, "sample-data-lake.json"), "-f", "sarif"],
    "graphsecure-cli": ["paths", "-i", os.path.join(FIXTURES_DIR, "sample-attack-graph.json"), "-f", "sarif"],
    "identitysecure-cli": ["escalations", "-i", os.path.join(FIXTURES_DIR, "sample-iam-directory.json"), "-f", "sarif"],
    "launchersecure-cli": ["pulse", "-f", "sarif"],
    "netsecure-cli": ["audit-rules", "-s", os.path.join(FIXTURES_DIR, "sample-security-groups.json"), "-o", "sarif"],
    "policysecure-cli": ["validate", "-p", os.path.join(FIXTURES_DIR, "sample-policy-pack.json"), "-o", "sarif"],
    "posturesecure-cli": ["scan", "-i", os.path.join(FIXTURES_DIR, "aws-cloud-inventory.json"), "-f", "sarif"],
    "supplysecure-cli": ["scan-dependencies", "-m", os.path.join(FIXTURES_DIR, "sample-package-manifest.json"), "-o", "sarif"],
    "threatsecure-cli": ["scan", "-i", os.path.join(FIXTURES_DIR, "sample-cloudtrail-stream.json"), "-f", "sarif"],
    "waassecure-cli": ["scan", "-i", os.path.join(FIXTURES_DIR, "sample-api-traffic.json"), "-f", "sarif"],
    "workloadsecure-cli": ["scan", "-i", os.path.join(FIXTURES_DIR, "sample-container-image.json"), "-f", "sarif"],
}

MCP_VALID_TOOL_CALLS = {
    "aisecure-cli": ("aispm_audit_inventory", {"inventory_json": "[]"}),
    "codesecure-cli": ("codesecure_scan_iac", {"files_json": "[]"}),
    "compliancesecure-cli": ("pulse_aggregate_posture", {"findings_json": "[]"}),
    "datasecure-cli": ("datasecure_classify_text", {"text": "clean text"}),
    "graphsecure-cli": ("graph_find_attack_paths", {"graph_json": "{\"nodes\":[],\"edges\":[]}"}),
    "identitysecure-cli": ("ciem_evaluate_permissions", {"principal_json": "{\"name\":\"test\",\"attached_policies\":[],\"inline_statements\":[]}"}),
    "launchersecure-cli": ("launcher_list_apps", {}),
    "netsecure-cli": ("cns_analyze_flow_logs", {"flows_json": "[]"}),
    "policysecure-cli": ("policy_parse_and_explain_rql", {"query": "config from cloud.resource where cloud.type = 'aws'"}),
    "posturesecure-cli": ("posture_evaluate_compliance", {"inventory_json": "[]"}),
    "supplysecure-cli": ("sscs_verify_slsa_provenance", {"provenance_json": "[]"}),
    "threatsecure-cli": ("threat_evaluate_audit_stream", {"events_json": "[]"}),
    "waassecure-cli": ("waas_inspect_traffic", {"traffic_json": "[]"}),
    "workloadsecure-cli": ("workload_scan_image", {"image_json": "{\"id\":\"img1\",\"repository\":\"nginx\",\"tag\":\"latest\",\"layers\":[]}"}),
}


class TestCliSubprocess(unittest.TestCase):

    def test_all_14_clis_help_flag(self):
        for cli_name in ALL_CLIS:
            cli_path = os.path.join(BIN_DIR, cli_name)
            self.assertTrue(os.path.exists(cli_path), f"Binary {cli_name} not found")
            res = subprocess.run(
                [sys.executable, cli_path, "--help"],
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, f"{cli_name} --help failed: {res.stderr}")
            self.assertTrue(len(res.stdout) > 0, f"{cli_name} --help produced no output")
            self.assertIn("usage:", res.stdout.lower(), f"{cli_name} help output missing usage string")

    def test_all_14_clis_sarif_output(self):
        for cli_name, cmd_args in SARIF_COMMANDS.items():
            cli_path = os.path.join(BIN_DIR, cli_name)
            full_cmd = [sys.executable, cli_path] + cmd_args
            res = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                cwd=PROJECT_ROOT,
                timeout=15,
            )
            self.assertIn(
                res.returncode,
                (0, 1),
                f"{cli_name} SARIF run failed with abnormal exit code {res.returncode} ({full_cmd}): {res.stderr}"
            )
            self.assertNotIn("Traceback", res.stderr, f"{cli_name} raised uncaught exception: {res.stderr}")

            try:
                sarif_doc = json.loads(res.stdout)
            except Exception as e:
                self.fail(f"{cli_name} did not return valid JSON for SARIF: {e}\nOutput was: {res.stdout[:500]}")

            self.assertIn("$schema", sarif_doc, f"{cli_name} SARIF missing $schema")
            self.assertIn("sarif-schema-2.1.0.json", sarif_doc["$schema"], f"{cli_name} $schema mismatch")
            self.assertEqual(sarif_doc.get("version"), "2.1.0", f"{cli_name} SARIF version is not 2.1.0")
            self.assertIn("runs", sarif_doc, f"{cli_name} SARIF missing runs")
            self.assertTrue(len(sarif_doc["runs"]) > 0, f"{cli_name} SARIF runs list is empty")

            run = sarif_doc["runs"][0]
            self.assertIn("tool", run, f"{cli_name} SARIF run missing tool")
            self.assertIn("driver", run["tool"], f"{cli_name} SARIF tool missing driver")
            self.assertIn("name", run["tool"]["driver"], f"{cli_name} SARIF driver missing name")
            self.assertIn("results", run, f"{cli_name} SARIF run missing results list")
            if cli_name == "posturesecure-cli":
                self.assertTrue(len(run["results"]) > 0, "posturesecure-cli should emit findings for aws-cloud-inventory.json")

    def test_all_14_clis_mcp_stdio_lifecycle(self):
        for cli_name in ALL_CLIS:
            cli_path = os.path.join(BIN_DIR, cli_name)
            proc = subprocess.Popen(
                [sys.executable, cli_path, "--mcp"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=PROJECT_ROOT,
            )

            try:
                # 1. Initialize request
                init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
                proc.stdin.write(json.dumps(init_req) + "\n")
                proc.stdin.flush()
                init_line = proc.stdout.readline()
                self.assertTrue(len(init_line) > 0, f"{cli_name} MCP initialize produced empty response")
                init_resp = json.loads(init_line)
                self.assertEqual(init_resp.get("id"), 1)
                self.assertIn("result", init_resp)
                self.assertEqual(init_resp["result"].get("protocolVersion"), "2024-11-05")
                self.assertIn("serverInfo", init_resp["result"])

                # 2. Notification: notifications/initialized (MUST produce no response line)
                notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                proc.stdin.write(json.dumps(notif) + "\n")

                # 3. Request: tools/list (should be the immediate next line on stdout)
                tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
                proc.stdin.write(json.dumps(tools_req) + "\n")
                proc.stdin.flush()
                tools_line = proc.stdout.readline()
                tools_resp = json.loads(tools_line)
                self.assertEqual(tools_resp.get("id"), 2, f"{cli_name} tools/list got unexpected id: {tools_resp}")
                self.assertIn("result", tools_resp)
                self.assertIn("tools", tools_resp["result"])
                tools_list = tools_resp["result"]["tools"]
                self.assertTrue(len(tools_list) > 0, f"{cli_name} MCP advertised zero tools")

                # 4. Unknown method returns error code -32601
                bad_req = {"jsonrpc": "2.0", "id": 3, "method": "nonexistent/action", "params": {}}
                proc.stdin.write(json.dumps(bad_req) + "\n")
                proc.stdin.flush()
                bad_line = proc.stdout.readline()
                bad_resp = json.loads(bad_line)
                self.assertEqual(bad_resp.get("id"), 3)
                self.assertIn("error", bad_resp)
                self.assertEqual(bad_resp["error"].get("code"), -32601)

                # 5. tools/call with unknown tool sets isError: True
                bad_tool_req = {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "__nonexistent_tool__", "arguments": {}},
                }
                proc.stdin.write(json.dumps(bad_tool_req) + "\n")
                proc.stdin.flush()
                bad_tool_line = proc.stdout.readline()
                bad_tool_resp = json.loads(bad_tool_line)
                self.assertEqual(bad_tool_resp.get("id"), 4)
                self.assertIn("result", bad_tool_resp)
                self.assertTrue(bad_tool_resp["result"].get("isError"), f"{cli_name} failed tools/call missing isError: True")

                # 6. tools/call with valid tool returns clean JSON text content without isError
                tool_name, tool_args = MCP_VALID_TOOL_CALLS[cli_name]
                ok_tool_req = {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": tool_args},
                }
                proc.stdin.write(json.dumps(ok_tool_req) + "\n")
                proc.stdin.flush()
                ok_tool_line = proc.stdout.readline()
                ok_tool_resp = json.loads(ok_tool_line)
                self.assertEqual(ok_tool_resp.get("id"), 5)
                self.assertIn("result", ok_tool_resp)
                self.assertFalse(ok_tool_resp["result"].get("isError", False), f"{cli_name} valid tool returned isError: {ok_tool_resp}")
                content_blocks = ok_tool_resp["result"].get("content", [])
                self.assertTrue(len(content_blocks) > 0)
                parsed_payload = json.loads(content_blocks[0]["text"])
                if isinstance(parsed_payload, dict):
                    self.assertNotIn("error", parsed_payload, f"{cli_name} valid tool returned error payload: {parsed_payload}")

            finally:
                proc.stdin.close()
                proc.stdout.close()
                proc.stderr.close()
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
