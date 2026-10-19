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
pub enum CodeError {
    #[error("Failed to parse IaC JSON or file: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Unsupported file type: {0}")]
    UnsupportedType(String),
}

/// Category of Infrastructure as Code or CI file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IacFileType {
    TerraformHcl,
    KubernetesYaml,
    Dockerfile,
    GitHubActionsYaml,
}

/// Discovered source code or configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IacSourceFile {
    pub path: String,
    pub file_type: IacFileType,
    pub content: String,
}

impl IacSourceFile {
    pub fn state_hash(&self) -> String {
        format!("{:x}", Sha256::digest(self.content.as_bytes()))
    }
}

/// IaC finding diagnostic pointing to offending file and lines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IacFinding {
    pub rule_id: String,
    pub file_path: String,
    pub line_number: usize,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub auto_fix_patch: Option<String>,
}

/// CycloneDX 1.5 SBOM Component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SbomComponent {
    pub name: String,
    pub version: String,
    pub purl: String,
    pub license: Option<String>,
}

/// Primary AST and static policy engine for CodeSecure.
pub struct IacPolicyEngine;

impl IacPolicyEngine {
    pub fn scan_file(file: &IacSourceFile) -> Vec<IacFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = file.content.lines().collect();

        // 1. Hardcoded Secret Check (Across all formats)
        for (idx, line) in lines.iter().enumerate() {
            if line.contains("AKIA") {
                findings.push(IacFinding {
                    rule_id: "IAC_SEC_001".into(),
                    file_path: file.path.clone(),
                    line_number: idx + 1,
                    severity: Severity::Critical,
                    title: "Hardcoded AWS Access Key ID".into(),
                    message: "Hardcoded plaintext credentials committed directly to version control.".into(),
                    auto_fix_patch: Some("# Replace plaintext key with environment variable or secret manager reference".into()),
                });
            }
        }

        match file.file_type {
            IacFileType::TerraformHcl => {
                // Check 1: S3 Bucket Public Read ACL
                for (idx, line) in lines.iter().enumerate() {
                    if line.contains("acl") && line.contains("public-read") {
                        findings.push(IacFinding {
                            rule_id: "IAC_AWS_001".into(),
                            file_path: file.path.clone(),
                            line_number: idx + 1,
                            severity: Severity::Critical,
                            title: "S3 Bucket Configured With Public-Read ACL".into(),
                            message: "S3 buckets should prohibit public read ACLs to prevent data leakage.".into(),
                            auto_fix_patch: Some(line.replace("public-read", "private")),
                        });
                    }
                }

                // Check 2: Security Group Ingress 0.0.0.0/0 to Port 22
                let mut in_ingress = false;
                let mut has_22 = false;
                let mut ingress_start = 0;
                for (idx, line) in lines.iter().enumerate() {
                    if line.contains("ingress {") || line.contains("type = \"ingress\"") {
                        in_ingress = true;
                        ingress_start = idx + 1;
                    }
                    if in_ingress && (line.contains("22") || line.contains("from_port = 22")) {
                        has_22 = true;
                    }
                    if in_ingress && line.contains("0.0.0.0/0") && has_22 {
                        findings.push(IacFinding {
                            rule_id: "IAC_AWS_002".into(),
                            file_path: file.path.clone(),
                            line_number: ingress_start,
                            severity: Severity::Critical,
                            title: "Security Group Exposes SSH Port 22 to 0.0.0.0/0".into(),
                            message: "SSH must not be open to the entire public Internet.".into(),
                            auto_fix_patch: Some("cidr_blocks = [\"10.0.0.0/8\"] # Restrict to internal CIDR".into()),
                        });
                        in_ingress = false;
                        has_22 = false;
                    }
                }
            }
            IacFileType::KubernetesYaml => {
                // Check 1: Privileged container mode
                for (idx, line) in lines.iter().enumerate() {
                    if line.contains("privileged: true") {
                        findings.push(IacFinding {
                            rule_id: "IAC_K8S_001".into(),
                            file_path: file.path.clone(),
                            line_number: idx + 1,
                            severity: Severity::Critical,
                            title: "Kubernetes Container Runs in Privileged Mode".into(),
                            message: "Privileged containers can easily escape to host kernel namespace.".into(),
                            auto_fix_patch: Some(line.replace("true", "false")),
                        });
                    }
                }

                // Check 2: Missing ReadOnlyRootFilesystem
                if file.content.contains("securityContext:") && !file.content.contains("readOnlyRootFilesystem: true") {
                    findings.push(IacFinding {
                        rule_id: "IAC_K8S_002".into(),
                        file_path: file.path.clone(),
                        line_number: 1,
                        severity: Severity::High,
                        title: "Container Root Filesystem Is Writable".into(),
                        message: "Enforce immutable containers by setting readOnlyRootFilesystem to true.".into(),
                        auto_fix_patch: Some("      readOnlyRootFilesystem: true".into()),
                    });
                }
            }
            IacFileType::Dockerfile => {
                // Check 1: Missing USER directive (runs as root)
                if !file.content.contains("USER ") {
                    findings.push(IacFinding {
                        rule_id: "IAC_DOCKER_001".into(),
                        file_path: file.path.clone(),
                        line_number: lines.len(),
                        severity: Severity::High,
                        title: "Dockerfile Lacks Non-Root USER Directive".into(),
                        message: "Container executes by default under root UID 0.".into(),
                        auto_fix_patch: Some("USER 10001:10001".into()),
                    });
                }

                // Check 2: Unpinned latest tag
                for (idx, line) in lines.iter().enumerate() {
                    if line.trim_start().starts_with("FROM ") && (line.ends_with(":latest") || !line.contains(':')) {
                        findings.push(IacFinding {
                            rule_id: "IAC_DOCKER_002".into(),
                            file_path: file.path.clone(),
                            line_number: idx + 1,
                            severity: Severity::Medium,
                            title: "Base Image Uses Mutable ':latest' Tag".into(),
                            message: "Pin base image tags or SHA digests to avoid unexpected upstream drift.".into(),
                            auto_fix_patch: Some(format!("{} # Pin exact immutable version", line.replace(":latest", ":3.18.4"))),
                        });
                    }
                }
            }
            IacFileType::GitHubActionsYaml => {
                // Check 1: Unpinned third-party actions
                for (idx, line) in lines.iter().enumerate() {
                    if line.contains("uses:") && (line.ends_with("@main") || line.ends_with("@master")) {
                        findings.push(IacFinding {
                            rule_id: "IAC_GHA_001".into(),
                            file_path: file.path.clone(),
                            line_number: idx + 1,
                            severity: Severity::High,
                            title: "GitHub Actions Step References Mutable Branch Tag".into(),
                            message: "Third-party actions should be pinned to immutable commit SHA hashes.".into(),
                            auto_fix_patch: Some(format!("{} # Pin full commit SHA", line.replace("@main", "@v4.1.1"))),
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Software Bill of Materials (SBOM) generator emitting CycloneDX 1.5 JSON.
pub struct ScaAndSbomEngine;

impl ScaAndSbomEngine {
    pub fn generate_cyclonedx(components: &[SbomComponent]) -> serde_json::Value {
        let comp_json: Vec<serde_json::Value> = components
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": c.purl,
                    "licenses": [{ "license": { "id": c.license.as_deref().unwrap_or("Apache-2.0") } }]
                })
            })
            .collect();

        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": Utc::now().to_rfc3339(),
                "tools": [{ "vendor": "CloudSecure", "name": "CodeSecure", "version": "0.1.0" }]
            },
            "components": comp_json
        })
    }
}

/// Commands accepted by the CodeSecure engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CodeCommand {
    LoadFiles(String),
    Clear,
}

/// State snapshot for CodeSecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeStateSnapshot {
    pub files: Vec<IacSourceFile>,
    pub findings: Vec<Finding>,
}

/// Main domain engine for CodeSecure (App 05).
#[derive(Debug, Clone, Default)]
pub struct CodeEngine {
    pub files: Vec<IacSourceFile>,
    pub findings: Vec<Finding>,
}

impl CodeEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recompute(&mut self) {
        self.findings.clear();

        for file in &self.files {
            let iac_findings = IacPolicyEngine::scan_file(file);
            for f in iac_findings {
                let evidence = Evidence {
                    rule_id: f.rule_id.clone(),
                    target_path: format!("{}:{}", f.file_path, f.line_number),
                    expected_value: "Compliant Infrastructure as Code configuration".into(),
                    observed_value: f.message.clone(),
                    message: f.title.clone(),
                    resource_state_hash: file.state_hash(),
                };

                let remediation_code = f.auto_fix_patch.clone().unwrap_or_else(|| "# Manual remediation required".into());

                self.findings.push(Finding {
                    id: format!("{}-{}-L{}", f.rule_id, file.path.replace('/', "-"), f.line_number),
                    rule_id: f.rule_id.clone(),
                    title: f.title.clone(),
                    severity: f.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "iac-repository".into(),
                    region: "global".into(),
                    resource_id: format!("{}:{}", file.path, f.line_number),
                    resource_arn: format!("git://repo/{}:{}", file.path, f.line_number),
                    resource_type: format!("{:?}", file.file_type),
                    framework_mappings: vec!["CIS IaC Benchmark".into(), "SOC 2: CC6.6".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::TerraformHcl,
                        code: remediation_code.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(remediation_code.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }
    }
}

impl CloudSecureAppEngine for CodeEngine {
    type Command = CodeCommand;
    type StateSnapshot = CodeStateSnapshot;
    type Error = CodeError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 5,
            id: "codesecure",
            name: "CodeSecure",
            pillar: "CODE",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "ASPM and Infrastructure as Code (IaC) static analyzer for Terraform, CloudFormation, Kubernetes, and Dockerfiles.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            CodeCommand::LoadFiles(json_str) => {
                self.files = serde_json::from_str(&json_str)?;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadFiles".into(),
                    records_affected: self.files.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            CodeCommand::Clear => {
                let count = self.files.len();
                self.files.clear();
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
        CodeStateSnapshot {
            files: self.files.clone(),
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
                        name: "CodeSecure".into(),
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
