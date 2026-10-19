use chrono::Utc;
use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, CloudProvider, Evidence, Finding, FindingStatus, RemediationFormat,
    RemediationPatch, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WorkloadError {
    #[error("Failed to parse image or runtime JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Image not found: '{0}'")]
    ImageNotFound(String),
}

/// Package record discovered inside an image layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

/// Dissected layer within an OCI container image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageLayer {
    pub layer_index: usize,
    pub created_by: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub packages: Vec<PackageInfo>,
    #[serde(default)]
    pub secrets_leaked: Vec<String>,
}

/// Inspected OCI/Docker container image manifest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub architecture: String,
    pub layers: Vec<ImageLayer>,
}

impl ContainerImage {
    pub fn state_hash(&self) -> String {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(serialized.as_bytes()))
    }
}

/// Matched CVE vulnerability with layer attribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveVulnerability {
    pub cve_id: String,
    pub package_name: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub cvss_score: f32,
    pub epss_score: f32,
    pub introduced_in_layer_index: usize,
    pub title: String,
    pub description: String,
}

/// Runtime event emitted from container host or eBPF sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub timestamp: String,
    pub container_id: String,
    pub process_executable: String,
    pub process_args: Vec<String>,
    pub parent_process: String,
    pub syscall: String,
    pub user_id: u32,
    pub is_root: bool,
}

/// Anomaly flagged by the runtime behavioral profiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAnomaly {
    pub anomaly_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub container_id: String,
}

/// Vulnerability matching engine linking packages to known CVE advisories.
pub struct VulnerabilityMatcher;

impl VulnerabilityMatcher {
    pub fn scan_image(image: &ContainerImage) -> Vec<CveVulnerability> {
        let mut vulns = Vec::new();

        for layer in &image.layers {
            for pkg in &layer.packages {
                // 1. Docker Auth Bypass
                if pkg.name == "docker" && pkg.version.starts_with("26.") {
                    vulns.push(CveVulnerability {
                        cve_id: "CVE-2024-41110".into(),
                        package_name: pkg.name.clone(),
                        installed_version: pkg.version.clone(),
                        fixed_version: Some("27.1.1".into()),
                        severity: Severity::Critical,
                        cvss_score: 10.0,
                        epss_score: 0.94,
                        introduced_in_layer_index: layer.layer_index,
                        title: "Docker Engine Authorization Bypass".into(),
                        description: "Bypass of AuthZ plugins enabling privilege escalation to host root.".into(),
                    });
                }

                // 2. OpenSSL Excessive DH Computation
                if pkg.name == "openssl" && pkg.version.starts_with("3.0.8") {
                    vulns.push(CveVulnerability {
                        cve_id: "CVE-2023-3817".into(),
                        package_name: pkg.name.clone(),
                        installed_version: pkg.version.clone(),
                        fixed_version: Some("3.0.10".into()),
                        severity: Severity::Medium,
                        cvss_score: 5.3,
                        epss_score: 0.12,
                        introduced_in_layer_index: layer.layer_index,
                        title: "OpenSSL Excessive DH Parameter Computation Denial of Service".into(),
                        description: "Flaw in DH_check() triggers CPU exhaustion upon parsing crafted parameters.".into(),
                    });
                }

                // 3. HTTP/2 Rapid Reset
                if (pkg.name == "nghttp2" || pkg.name == "envoy") && pkg.version.starts_with("1.25.") {
                    vulns.push(CveVulnerability {
                        cve_id: "CVE-2023-44487".into(),
                        package_name: pkg.name.clone(),
                        installed_version: pkg.version.clone(),
                        fixed_version: Some("1.26.0".into()),
                        severity: Severity::High,
                        cvss_score: 7.5,
                        epss_score: 0.88,
                        introduced_in_layer_index: layer.layer_index,
                        title: "HTTP/2 Rapid Reset Stream Cancellation Exhaustion".into(),
                        description: "Flooding RST_STREAM frames induces severe resource exhaustion on HTTP/2 servers.".into(),
                    });
                }
            }
        }

        vulns
    }
}

/// Runtime behavioral engine evaluating process, syscall, and privilege events.
pub struct RuntimeAnomalyDetector;

impl RuntimeAnomalyDetector {
    pub fn evaluate_event(event: &RuntimeEvent) -> Vec<RuntimeAnomaly> {
        let mut anomalies = Vec::new();

        // Rule 1: Interactive shell spawned inside production container
        let is_shell = event.process_executable.ends_with("/sh")
            || event.process_executable.ends_with("/bash")
            || event.process_executable.ends_with("/zsh");

        let parent_is_daemon = event.parent_process.contains("nginx")
            || event.parent_process.contains("node")
            || event.parent_process.contains("python")
            || event.parent_process.contains("gunicorn");

        if is_shell && parent_is_daemon {
            anomalies.push(RuntimeAnomaly {
                anomaly_id: format!("ANOM-{}", event.event_id),
                rule_id: "CWPP-RT-001".into(),
                severity: Severity::Critical,
                title: "Unexpected Shell Spawned by Daemon Process".into(),
                description: format!(
                    "Production daemon '{}' spawned interactive shell '{}' inside container '{}'. Potential RCE exploitation.",
                    event.parent_process, event.process_executable, event.container_id
                ),
                container_id: event.container_id.clone(),
            });
        }

        // Rule 2: Root process execution
        if event.is_root && event.user_id == 0 {
            anomalies.push(RuntimeAnomaly {
                anomaly_id: format!("ANOM-ROOT-{}", event.event_id),
                rule_id: "CWPP-RT-002".into(),
                severity: Severity::High,
                title: "Container Process Running as Root UID 0".into(),
                description: format!(
                    "Process '{}' is executing with root UID 0 inside container '{}'.",
                    event.process_executable, event.container_id
                ),
                container_id: event.container_id.clone(),
            });
        }

        // Rule 3: Dangerous escape syscall
        if event.syscall == "ptrace" || event.syscall == "reboot" || event.syscall == "setns" {
            anomalies.push(RuntimeAnomaly {
                anomaly_id: format!("ANOM-SYS-{}", event.event_id),
                rule_id: "CWPP-RT-003".into(),
                severity: Severity::Critical,
                title: "Dangerous Container Escape Syscall Invocation".into(),
                description: format!(
                    "Process '{}' invoked restricted syscall '{}' inside container '{}'.",
                    event.process_executable, event.syscall, event.container_id
                ),
                container_id: event.container_id.clone(),
            });
        }

        anomalies
    }
}

/// Generates hardened Kubernetes security context manifests.
pub struct KubernetesHardeningSynthesizer;

impl KubernetesHardeningSynthesizer {
    pub fn synthesize_security_context(container_name: &str) -> String {
        format!(
            r#"# Hardened Kubernetes SecurityContext for {}
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 10001
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
  seccompProfile:
    type: RuntimeDefault"#,
            container_name
        )
    }
}

/// Commands accepted by WorkloadSecure engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkloadCommand {
    LoadImages(String),
    LoadRuntimeEvents(String),
    Clear,
}

/// State snapshot for WorkloadSecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadStateSnapshot {
    pub images: Vec<ContainerImage>,
    pub vulnerabilities: Vec<CveVulnerability>,
    pub runtime_anomalies: Vec<RuntimeAnomaly>,
    pub findings: Vec<Finding>,
}

/// Main domain engine for WorkloadSecure (App 03).
#[derive(Debug, Clone, Default)]
pub struct WorkloadEngine {
    pub images: Vec<ContainerImage>,
    pub vulnerabilities: Vec<CveVulnerability>,
    pub runtime_anomalies: Vec<RuntimeAnomaly>,
    pub findings: Vec<Finding>,
}

impl WorkloadEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recompute(&mut self) {
        self.vulnerabilities.clear();
        self.findings.clear();

        for img in &self.images {
            let vulns = VulnerabilityMatcher::scan_image(img);
            for v in &vulns {
                let evidence = Evidence {
                    rule_id: v.cve_id.clone(),
                    target_path: format!("layers[{}].packages[{}]", v.introduced_in_layer_index, v.package_name),
                    expected_value: format!("Fixed version >= {:?}", v.fixed_version),
                    observed_value: format!("Vulnerable version {}", v.installed_version),
                    message: format!("{}: {}", v.title, v.description),
                    resource_state_hash: img.state_hash(),
                };

                let hcl = KubernetesHardeningSynthesizer::synthesize_security_context(&img.repository);

                self.findings.push(Finding {
                    id: format!("{}-{}", v.cve_id, img.id),
                    rule_id: v.cve_id.clone(),
                    title: format!("{}: {}", v.cve_id, v.package_name),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::K8s,
                    account_id: "workloads".into(),
                    region: "global".into(),
                    resource_id: img.id.clone(),
                    resource_arn: format!("oci://{}:{}", img.repository, img.tag),
                    resource_type: "ContainerImage".into(),
                    framework_mappings: vec!["NIST SP 800-190".into(), "PCI-DSS: 6.2".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::KubernetesYaml,
                        code: hcl.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(hcl.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
            self.vulnerabilities.extend(vulns);

            // Check for deleted layer secret leaks
            for layer in &img.layers {
                for secret in &layer.secrets_leaked {
                    let evidence = Evidence {
                        rule_id: "CWPP-SEC-001".into(),
                        target_path: format!("layers[{}].created_by", layer.layer_index),
                        expected_value: "Zero secret keys or tokens in container build history".into(),
                        observed_value: format!("Leaked credential in layer build command: {}", secret),
                        message: "Secret committed to image layer remains in metadata even if deleted subsequently.".into(),
                        resource_state_hash: img.state_hash(),
                    };

                    self.findings.push(Finding {
                        id: format!("CWPP-SEC-001-{}-L{}", img.id, layer.layer_index),
                        rule_id: "CWPP-SEC-001".into(),
                        title: "Secret Token Leaked in Container Build Layer".into(),
                        severity: Severity::Critical,
                        status: FindingStatus::Fail,
                        provider: CloudProvider::K8s,
                        account_id: "workloads".into(),
                        region: "global".into(),
                        resource_id: img.id.clone(),
                        resource_arn: format!("oci://{}:{}", img.repository, img.tag),
                        resource_type: "ContainerLayer".into(),
                        framework_mappings: vec!["CIS Docker: 4.1".into(), "SOC 2: CC6.1".into()],
                        evidence,
                        remediation: None,
                        timestamp: Utc::now(),
                    });
                }
            }
        }
    }

    pub fn ingest_runtime_events(&mut self, events_json: &str) -> Result<usize, WorkloadError> {
        let events: Vec<RuntimeEvent> = serde_json::from_str(events_json)?;
        let count = events.len();
        for ev in &events {
            let anoms = RuntimeAnomalyDetector::evaluate_event(ev);
            for a in &anoms {
                let evidence = Evidence {
                    rule_id: a.rule_id.clone(),
                    target_path: format!("containers[{}].processes[{}]", ev.container_id, ev.process_executable),
                    expected_value: "Execution matches behavioral baseline profile".into(),
                    observed_value: a.description.clone(),
                    message: a.title.clone(),
                    resource_state_hash: format!("{:x}", Sha256::digest(ev.event_id.as_bytes())),
                };

                self.findings.push(Finding {
                    id: format!("{}-{}", a.rule_id, ev.event_id),
                    rule_id: a.rule_id.clone(),
                    title: a.title.clone(),
                    severity: a.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::K8s,
                    account_id: "runtime".into(),
                    region: "global".into(),
                    resource_id: ev.container_id.clone(),
                    resource_arn: format!("k8s://pod/{}", ev.container_id),
                    resource_type: "PodRuntime".into(),
                    framework_mappings: vec!["MITRE ATT&CK: Execution".into(), "CIS K8s: 5.1".into()],
                    evidence,
                    remediation: None,
                    timestamp: Utc::now(),
                });
            }
            self.runtime_anomalies.extend(anoms);
        }
        Ok(count)
    }
}

impl CloudSecureAppEngine for WorkloadEngine {
    type Command = WorkloadCommand;
    type StateSnapshot = WorkloadStateSnapshot;
    type Error = WorkloadError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 3,
            id: "workloadsecure",
            name: "WorkloadSecure",
            pillar: "WORKLOAD",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "CWPP container image layer analyzer, CVE vulnerability matcher, and runtime profile generator.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            WorkloadCommand::LoadImages(json_str) => {
                self.images = serde_json::from_str(&json_str)?;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadImages".into(),
                    records_affected: self.images.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            WorkloadCommand::LoadRuntimeEvents(json_str) => {
                let count = self.ingest_runtime_events(&json_str)?;
                Ok(CommandReceipt {
                    command_name: "LoadRuntimeEvents".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("runtime-{}", count),
                })
            }
            WorkloadCommand::Clear => {
                let count = self.images.len();
                self.images.clear();
                self.vulnerabilities.clear();
                self.runtime_anomalies.clear();
                self.findings.clear();
                Ok(CommandReceipt {
                    command_name: "Clear".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "empty".into(),
                })
            }
        }
    }

    fn snapshot(&self) -> Self::StateSnapshot {
        WorkloadStateSnapshot {
            images: self.images.clone(),
            vulnerabilities: self.vulnerabilities.clone(),
            runtime_anomalies: self.runtime_anomalies.clone(),
            findings: self.findings.clone(),
        }
    }

    fn export_sarif(&self) -> SarifReport {
        let mut rules = Vec::new();
        let mut results = Vec::new();

        for f in &self.findings {
            rules.push(SarifRule {
                id: f.rule_id.clone(),
                name: f.title.clone(),
                short_description: SarifMessage {
                    text: f.evidence.message.clone(),
                },
            });

            results.push(SarifResult {
                rule_id: f.rule_id.clone(),
                level: if f.severity == Severity::Critical { "error" } else { "warning" }.into(),
                message: SarifMessage {
                    text: format!("{}: {}", f.title, f.evidence.message),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.resource_arn.clone(),
                        },
                    },
                }],
            });
        }

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "WorkloadSecure".into(),
                        version: "0.1.0".into(),
                        information_uri: "https://github.com/kennyanju/plantainchips".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
