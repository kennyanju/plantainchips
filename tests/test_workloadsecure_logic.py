import json, unittest, hashlib, importlib.machinery, importlib.util

def load_workload_cli():
    loader = importlib.machinery.SourceFileLoader("workloadcli", "bin/workloadsecure-cli")
    spec = importlib.util.spec_from_loader(loader.name, loader)
    cli = importlib.util.module_from_spec(spec)
    loader.exec_module(cli)
    return cli

class TestWorkloadSecureEngine(unittest.TestCase):
    def setUp(self):
        with open("fixtures/sample-container-image.json", "r", encoding="utf-8") as f:
            self.images = json.load(f)
        with open("fixtures/sample-runtime-events.json", "r", encoding="utf-8") as f:
            self.events = json.load(f)
        self.cli = load_workload_cli()

    def test_image_layers_and_packages_loaded(self):
        self.assertEqual(len(self.images), 1)
        img = self.images[0]
        self.assertEqual(len(img["layers"]), 4)
        layer2 = img["layers"][2]
        self.assertEqual(layer2["packages"][0]["name"], "docker")
        self.assertEqual(layer2["secrets_leaked"], ["AKIAIOSFODNN7EXAMPLE"])

    def test_layer_attributed_cve_scanning(self):
        img = self.images[0]
        findings = self.cli.scan_image(img)
        self.assertEqual(len(findings), 5)

        cve_ids = {v["cve_id"] for v in findings}
        self.assertIn("CVE-2024-41110", cve_ids)
        self.assertIn("CVE-2023-3817", cve_ids)
        self.assertIn("CVE-2023-2650", cve_ids)
        self.assertIn("CVE-2023-44487", cve_ids)
        self.assertIn("LAYER-SECRET-001", cve_ids)

        docker_cve = next(v for v in findings if v["cve_id"] == "CVE-2024-41110")
        self.assertEqual(docker_cve["introduced_in_layer_index"], 2)
        self.assertEqual(docker_cve["severity"], "CRITICAL")
        self.assertEqual(docker_cve["cvss_score"], 10.0)
        self.assertTrue(docker_cve["cisa_kev"])

        secret_leak = next(v for v in findings if v["cve_id"] == "LAYER-SECRET-001")
        self.assertEqual(secret_leak["introduced_in_layer_index"], 2)
        self.assertEqual(secret_leak["type"], "SECRET_LEAK")

    def test_runtime_behavioral_anomalies(self):
        anomalies = []
        for ev in self.events:
            anomalies.extend(self.cli.evaluate_runtime_event(ev))

        self.assertEqual(len(anomalies), 4)
        rule_ids = [a["rule_id"] for a in anomalies]
        self.assertIn("CWPP-RT-001", rule_ids)
        self.assertIn("CWPP-RT-002", rule_ids)
        self.assertIn("CWPP-RT-003", rule_ids)

        # Verify clean event 4 (gunicorn) generates no anomalies
        clean_ev = self.events[3]
        clean_anoms = self.cli.evaluate_runtime_event(clean_ev)
        self.assertEqual(len(clean_anoms), 0)

        # Test cryptomining detection (CWPP-RT-004)
        miner_ev = {
            "event_id": "miner-01",
            "process_executable": "/tmp/xmrig",
            "process_args": ["-o", "stratum+tcp://xmr.pool:3333"],
            "parent_process": "sh",
            "syscall": "connect",
            "container_id": "c-miner",
            "is_root": False
        }
        miner_anoms = self.cli.evaluate_runtime_event(miner_ev)
        self.assertEqual(len(miner_anoms), 1)
        self.assertEqual(miner_anoms[0]["rule_id"], "CWPP-RT-004")

        # Test sensitive file access detection (CWPP-RT-005)
        file_ev = {
            "event_id": "file-01",
            "process_executable": "/bin/cat",
            "process_args": ["/etc/shadow"],
            "parent_process": "bash",
            "syscall": "openat",
            "container_id": "c-probe",
            "is_root": True
        }
        file_anoms = self.cli.evaluate_runtime_event(file_ev)
        self.assertTrue(any(a["rule_id"] == "CWPP-RT-005" for a in file_anoms))

    def test_pod_security_audit(self):
        risky_pod = {
            "spec": {
                "hostNetwork": True,
                "hostPID": True,
                "containers": [
                    {
                        "name": "privileged-agent",
                        "securityContext": {
                            "privileged": True,
                            "runAsUser": 0,
                            "capabilities": {"add": ["CAP_SYS_ADMIN"]}
                        }
                    }
                ],
                "volumes": [
                    {
                        "name": "docker-sock",
                        "hostPath": {"path": "/var/run/docker.sock"}
                    }
                ]
            }
        }
        violations = self.cli.audit_pod_security(risky_pod)
        v_rules = {v["rule_id"] for v in violations}
        self.assertIn("PSS-HOST-NETWORK", v_rules)
        self.assertIn("PSS-HOST-PID", v_rules)
        self.assertIn("PSS-PRIVILEGED", v_rules)
        self.assertIn("PSS-ROOT-USER", v_rules)
        self.assertIn("PSS-DANGEROUS-CAP", v_rules)
        self.assertIn("PSS-DOCKER-SOCK-MOUNT", v_rules)

    def test_kubernetes_hardening_synthesis(self):
        yaml_output = self.cli.synthesize_hardening_yaml("ecommerce-frontend")
        self.assertIn("allowPrivilegeEscalation: false", yaml_output)
        self.assertIn("readOnlyRootFilesystem: true", yaml_output)
        self.assertIn("runAsNonRoot: true", yaml_output)
        self.assertIn("type: RuntimeDefault", yaml_output)

        seccomp_prof = self.cli.synthesize_seccomp_profile()
        self.assertEqual(seccomp_prof["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertIn("SCMP_ARCH_X86_64", seccomp_prof["architectures"])
        self.assertIn("epoll_create1", seccomp_prof["syscalls"][0]["names"])

    def test_image_state_hash_determinism(self):
        img = self.images[0]
        h1 = hashlib.sha256(json.dumps(img, sort_keys=True).encode("utf-8")).hexdigest()
        h2 = hashlib.sha256(json.dumps(img, sort_keys=True).encode("utf-8")).hexdigest()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

if __name__ == "__main__":
    unittest.main()
