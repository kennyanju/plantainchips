//! ComplianceSecure: Executive Command Center and Multi-Framework Compliance Audit Engine
//!
//! Ingests posture findings across all 12 CloudSecure sister modules (Posture, Data,
//! Workload, Identity, Code, WAAS, Threat, Graph, Net, AI, Supply, Policy) into a
//! unified CNAPP risk ledger. Ranks the Prioritized Top-10 Breach-Stopping Remediation
//! Queue by cross-pillar blast-radius reduction and compiles signed audit packages
//! for SOC 2, ISO 27001, PCI-DSS v4, HIPAA, NIST CSF 2.0, and FedRAMP.

use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, Finding, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// Supported compliance frameworks in ComplianceSecure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Soc2Type2,
    Iso27001_2022,
    PciDssV4,
    HipaaSecurity,
    NistCsf2,
    FedrampModerate,
}

impl ComplianceFramework {
    pub fn id_code(&self) -> &'static str {
        match self {
            Self::Soc2Type2 => "soc2",
            Self::Iso27001_2022 => "iso27001",
            Self::PciDssV4 => "pci",
            Self::HipaaSecurity => "hipaa",
            Self::NistCsf2 => "nist",
            Self::FedrampModerate => "fedramp",
        }
    }

    pub fn display_title(&self) -> &'static str {
        match self {
            Self::Soc2Type2 => "SOC 2 Type II (Trust Services Criteria)",
            Self::Iso27001_2022 => "ISO/IEC 27001:2022 Information Security",
            Self::PciDssV4 => "PCI-DSS v4.0 Payment Card Industry Standard",
            Self::HipaaSecurity => "HIPAA Security Rule (45 CFR Part 164)",
            Self::NistCsf2 => "NIST Cybersecurity Framework 2.0",
            Self::FedrampModerate => "FedRAMP Moderate Security Baseline",
        }
    }

    pub fn total_controls(&self) -> usize {
        match self {
            Self::Soc2Type2 => 6,
            Self::Iso27001_2022 => 5,
            Self::PciDssV4 => 6,
            Self::HipaaSecurity => 4,
            Self::NistCsf2 => 6,
            Self::FedrampModerate => 5,
        }
    }

    pub fn parse_code(s: &str) -> Option<Self> {
        match s.to_lowercase().trim() {
            "soc2" | "soc2_type2" | "soc-2" => Some(Self::Soc2Type2),
            "iso27001" | "iso_27001" | "iso" => Some(Self::Iso27001_2022),
            "pci" | "pci_dss" | "pci-dss" | "pcidss" => Some(Self::PciDssV4),
            "hipaa" | "hipaa_security" => Some(Self::HipaaSecurity),
            "nist" | "nist_csf" | "nistcsf" => Some(Self::NistCsf2),
            "fedramp" | "fedramp_moderate" => Some(Self::FedrampModerate),
            _ => None,
        }
    }
}

/// Status of an individual framework control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlStatus {
    Passed,
    Failed,
    NotApplicable,
}

/// Detailed compliance framework control evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameworkControl {
    pub control_id: String,
    pub framework: String,
    pub title: String,
    pub description: String,
    pub status: ControlStatus,
    pub failing_findings_count: usize,
    pub findings_refs: Vec<String>,
}

/// An entry in the Prioritized Top-10 Breach-Stopping Remediation Queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrioritizedRemediation {
    pub rank: usize,
    pub remediation_id: String,
    pub title: String,
    pub source_module: String,
    pub resource_id: String,
    pub severity: Severity,
    pub blast_radius_reduction_score: f64,
    pub affected_framework_controls: Vec<String>,
    pub remediation_command: String,
}

/// High-level executive readiness summary for a specific framework.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrameworkReadinessSummary {
    pub framework: String,
    pub display_title: String,
    pub total_controls: usize,
    pub passed_controls: usize,
    pub failed_controls: usize,
    pub readiness_percentage: f64,
    pub critical_findings: usize,
    pub high_findings: usize,
}

/// Cryptographically sealed compliance audit evidence bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvidenceBundle {
    pub bundle_id: String,
    pub framework: String,
    pub compiled_at: String,
    pub organization: String,
    pub readiness_percentage: f64,
    pub total_findings_evaluated: usize,
    pub controls: Vec<FrameworkControl>,
    pub top_remediations: Vec<PrioritizedRemediation>,
    pub manifest_sha256: String,
}

/// Raw ingested posture finding across any sibling CloudSecure module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngestedPostureFinding {
    pub id: String,
    pub rule_id: String,
    pub source_module: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub resource_id: String,
    #[serde(default)]
    pub cloud_type: String,
    #[serde(default)]
    pub account_id: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub evidence_detail: String,
    #[serde(default)]
    pub remediation_action: String,
    #[serde(default)]
    pub framework_controls: Vec<String>,
}

impl IngestedPostureFinding {
    pub fn state_hash(&self) -> String {
        let raw = format!("{}:{}:{}:{}", self.id, self.source_module, self.severity.as_str(), self.resource_id);
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }
}

/// Unified Posture Aggregator and Audit Compiler Engine.
pub struct UnifiedPostureAggregator {
    pub findings: Vec<IngestedPostureFinding>,
}

impl Default for UnifiedPostureAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedPostureAggregator {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn ingest_findings(&mut self, findings: Vec<IngestedPostureFinding>) {
        self.findings.extend(findings);
        self.deduplicate();
    }

    fn deduplicate(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.findings.retain(|f| seen.insert(format!("{}:{}:{}", f.source_module, f.rule_id, f.resource_id)));
    }

    /// Computes the Prioritized Top-10 Breach-Stopping Remediation Queue ranked by blast-radius reduction.
    pub fn prioritize_remediations(&self) -> Vec<PrioritizedRemediation> {
        let mut scored: Vec<(f64, &IngestedPostureFinding)> = self.findings.iter().map(|f| {
            let base_score = match f.severity {
                Severity::Critical => 40.0,
                Severity::High => 25.0,
                Severity::Medium => 10.0,
                Severity::Low => 3.0,
                Severity::Informational => 1.0,
            };

            let module_multiplier = match f.source_module.as_str() {
                "graphsecure" => 1.40,
                "threatsecure" => 1.35,
                "datasecure" => 1.30,
                "waassecure" => 1.25,
                "aisecure" => 1.20,
                "identitysecure" => 1.15,
                "supplysecure" => 1.10,
                _ => 1.05,
            };

            let control_bonus = (f.framework_controls.len() as f64) * 5.0;
            let final_score = (base_score * module_multiplier) + control_bonus;
            (final_score, f)
        }).collect();

        // Sort descending by blast-radius score
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        scored.into_iter().take(10).enumerate().map(|(idx, (score, f))| {
            PrioritizedRemediation {
                rank: idx + 1,
                remediation_id: format!("REM-{:02}", idx + 1),
                title: f.title.clone(),
                source_module: f.source_module.clone(),
                resource_id: f.resource_id.clone(),
                severity: f.severity,
                blast_radius_reduction_score: (score * 10.0).round() / 10.0,
                affected_framework_controls: f.framework_controls.clone(),
                remediation_command: f.remediation_action.clone(),
            }
        }).collect()
    }

    /// Evaluates controls and calculates executive readiness for a given framework.
    pub fn evaluate_framework(&self, framework: ComplianceFramework) -> FrameworkReadinessSummary {
        let controls = self.compile_controls_for_framework(framework);
        let total = controls.len();
        let passed = controls.iter().filter(|c| c.status == ControlStatus::Passed).count();
        let failed = total.saturating_sub(passed);

        let percentage = if total > 0 {
            ((passed as f64) / (total as f64)) * 100.0
        } else {
            100.0
        };

        let mut criticals = 0;
        let mut highs = 0;
        for f in &self.findings {
            let matches_fw = f.framework_controls.iter().any(|c| control_matches_framework(c, framework));
            if matches_fw {
                match f.severity {
                    Severity::Critical => criticals += 1,
                    Severity::High => highs += 1,
                    _ => {}
                }
            }
        }

        FrameworkReadinessSummary {
            framework: framework.id_code().into(),
            display_title: framework.display_title().into(),
            total_controls: total,
            passed_controls: passed,
            failed_controls: failed,
            readiness_percentage: (percentage * 10.0).round() / 10.0,
            critical_findings: criticals,
            high_findings: highs,
        }
    }

    /// Compiles control statuses for a specified framework.
    pub fn compile_controls_for_framework(&self, framework: ComplianceFramework) -> Vec<FrameworkControl> {
        let baseline = get_framework_baseline(framework);
        let mut controls = Vec::new();

        for (cid, title, desc) in baseline {
            let mut failing_refs = Vec::new();

            for f in &self.findings {
                for c_ref in &f.framework_controls {
                    if c_ref.to_lowercase().contains(&cid.to_lowercase()) {
                        failing_refs.push(format!("{}: {}", f.id, f.title));
                        break;
                    }
                }
            }

            let status = if failing_refs.is_empty() {
                ControlStatus::Passed
            } else {
                ControlStatus::Failed
            };

            controls.push(FrameworkControl {
                control_id: cid.to_string(),
                framework: framework.id_code().to_string(),
                title: title.to_string(),
                description: desc.to_string(),
                status,
                failing_findings_count: failing_refs.len(),
                findings_refs: failing_refs,
            });
        }

        controls
    }

    /// Compiles a complete, deterministically signed audit evidence bundle.
    pub fn compile_bundle(&self, framework: ComplianceFramework, organization: &str) -> AuditEvidenceBundle {
        let controls = self.compile_controls_for_framework(framework);
        let top_remediations = self.prioritize_remediations();
        let readiness = self.evaluate_framework(framework);

        let mut hasher = Sha256::new();
        hasher.update(framework.id_code().as_bytes());
        hasher.update(organization.as_bytes());
        for c in &controls {
            hasher.update(format!("{}:{:?}:{}", c.control_id, c.status, c.failing_findings_count).as_bytes());
        }
        for r in &top_remediations {
            hasher.update(format!("{}:{}:{}", r.rank, r.resource_id, r.blast_radius_reduction_score).as_bytes());
        }
        let manifest_hash = format!("{:x}", hasher.finalize());

        AuditEvidenceBundle {
            bundle_id: format!("BUNDLE-{}-{}", framework.id_code().to_uppercase(), &manifest_hash[..8]),
            framework: framework.display_title().into(),
            compiled_at: chrono::Utc::now().to_rfc3339(),
            organization: organization.into(),
            readiness_percentage: readiness.readiness_percentage,
            total_findings_evaluated: self.findings.len(),
            controls,
            top_remediations,
            manifest_sha256: manifest_hash,
        }
    }
}

/// Baseline control definitions for each compliance standard.
fn get_framework_baseline(framework: ComplianceFramework) -> Vec<(&'static str, &'static str, &'static str)> {
    match framework {
        ComplianceFramework::Soc2Type2 => vec![
            ("CC6.1", "Logical Access Controls & Public Perimeter Defense", "Restricts public exposure and access to authorized internal principals."),
            ("CC6.3", "Principle of Least Privilege & Entitlement Management", "Disallows excessive and administrative wildcard IAM permissions."),
            ("CC6.6", "Network Boundary & Choke Point Defense", "Enforces segmentation and firewalls between external Internet and crown-jewel assets."),
            ("CC6.8", "Container & Workload Runtime Protection", "Guards workloads against container breakouts, malware, and root execution."),
            ("CC7.2", "Continuous Security Monitoring & Anomaly Detection", "Detects command-and-control beacons and unauthorized security events."),
            ("CC8.1", "Software Supply Chain Integrity & Change Management", "Enforces immutable build provenance and dependency trust gates."),
        ],
        ComplianceFramework::Iso27001_2022 => vec![
            ("A.9.2", "User Access Provisioning and Privileged Access", "Governs allocation and review of privileged identity access rights."),
            ("A.12.2", "Protection Against Malicious Code and C2", "Implements controls to detect and isolate unauthorized beaconing software."),
            ("A.13.1", "Network Security Management and Ingress Segregation", "Restricts inbound traffic from untrusted public networks."),
            ("A.8.24", "Use of Cryptography and Key Management", "Enforces cryptographic encryption across data storage and transmission."),
            ("A.8.28", "Secure Coding & Supply Chain Assurance", "Verifies third-party package dependencies against confusion attacks."),
        ],
        ComplianceFramework::PciDssV4 => vec![
            ("1.2", "Inbound and Outbound Network Traffic Restrictions", "Restricts ingress traffic to cardholder environments and public buckets."),
            ("1.3", "Prohibit Direct Internet Exposure to Internal Services", "Prevents direct routing from Internet to sensitive storage or SSH port 22."),
            ("3.4", "Cardholder Data Encryption at Rest", "Requires cryptographic protection of stored data and automated backups."),
            ("6.4", "Public-Facing Web Application Attack Protection", "Guards against injection, SQLi, and OWASP API security vulnerabilities."),
            ("8.2", "Authentication Credential Management", "Prohibits hardcoded plain-text credentials and access keys in source code."),
            ("11.5", "Intrusion Detection and File Integrity Monitoring", "Monitors workload behavior for unauthorized execution or compromise."),
        ],
        ComplianceFramework::HipaaSecurity => vec![
            ("164.312", "Technical Safeguards: Access Control & Data Protection", "Restricts ePHI exposure to authorized workforce members."),
            ("164.312(a)(2)(iv)", "Encryption and Decryption at Rest", "Mandates encryption for database snapshots and persistent volumes."),
            ("164.312(b)", "Audit Controls and Activity Logging", "Requires continuous logging of access and anomalous behaviors."),
            ("164.312(e)(1)", "Transmission Security and Network Encryption", "Enforces secure encrypted transport channels across network perimeters."),
        ],
        ComplianceFramework::NistCsf2 => vec![
            ("PR.AC-5", "Network Integrity and Ingress Segregation", "Prevents unauthorized lateral network access across cloud environments."),
            ("PR.DS-1", "Data-at-Rest Confidentiality and Protection", "Guards confidential data and AI model weights from unauthorized disclosure."),
            ("PR.IP-1", "Baseline Configuration & Least Privilege", "Maintains baseline configurations preventing root container execution."),
            ("DE.CM-1", "Adversary Activity and Anomaly Monitoring", "Detects malicious network communication and command-and-control activity."),
            ("SA-11", "Supply Chain Security Integrity Verification", "Verifies software build provenance and protects against dependency hijacking."),
            ("RS.RP-1", "Incident Response Execution and Containment", "Executes automated containment on hosts exhibiting active compromise."),
        ],
        ComplianceFramework::FedrampModerate => vec![
            ("AC-2", "Account Management and Least Privilege Review", "Requires automated auditing of inactive administrative IAM accounts."),
            ("SC-7", "Boundary Protection and Ingress Filtering", "Enforces boundary protection against public Internet exposure."),
            ("SI-7", "Software, Firmware, and Information Integrity", "Verifies cryptographic signatures and immutable commit references."),
            ("SI-4", "System Monitoring and Intrusion Detection", "Continuously monitors cloud traffic for anomalous DNS tunneling."),
            ("SC-28", "Protection of Information at Rest with KMS", "Protects cloud databases and backups using FIPS 140-2 validated encryption."),
        ],
    }
}

fn control_matches_framework(ctrl_ref: &str, framework: ComplianceFramework) -> bool {
    let lower = ctrl_ref.to_lowercase();
    match framework {
        ComplianceFramework::Soc2Type2 => lower.contains("soc2") || lower.contains("cc6") || lower.contains("cc7") || lower.contains("cc8"),
        ComplianceFramework::Iso27001_2022 => lower.contains("iso") || lower.contains("a.9") || lower.contains("a.12") || lower.contains("a.13"),
        ComplianceFramework::PciDssV4 => lower.contains("pci"),
        ComplianceFramework::HipaaSecurity => lower.contains("hipaa") || lower.contains("164.312"),
        ComplianceFramework::NistCsf2 => lower.contains("nist"),
        ComplianceFramework::FedrampModerate => lower.contains("fedramp") || lower.contains("si-7") || lower.contains("ac-2"),
    }
}

/// Formatter generating Markdown, CSV, and SARIF exports from an AuditEvidenceBundle.
pub struct AuditBundleExporter;

impl AuditBundleExporter {
    pub fn to_markdown(bundle: &AuditEvidenceBundle) -> String {
        let mut md = String::new();
        md.push_str(&format!("# Executive Compliance Audit Report: {}\n\n", bundle.framework));
        md.push_str(&format!("- **Organization**: {}\n", bundle.organization));
        md.push_str(&format!("- **Compiled At**: {}\n", bundle.compiled_at));
        md.push_str(&format!("- **Readiness Score**: {:.1}%\n", bundle.readiness_percentage));
        md.push_str(&format!("- **Evidence Bundle SHA-256**: `{}`\n\n", bundle.manifest_sha256));

        md.push_str("## 1. Prioritized Top-10 Breach-Stopping Remediation Queue\n\n");
        md.push_str("| Rank | Title | Source Module | Severity | Blast Radius Reduction | Remediation Action |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- | :--- |\n");
        for r in &bundle.top_remediations {
            md.push_str(&format!(
                "| #{} | {} | `{}` | **{}** | **{:.1}** | `{}` |\n",
                r.rank, r.title, r.source_module, r.severity.as_str(), r.blast_radius_reduction_score, r.remediation_command
            ));
        }

        md.push_str("\n## 2. Control-by-Control Audit Evidence Table\n\n");
        md.push_str("| Control ID | Title | Status | Failing Findings | Evidence & Findings Summary |\n");
        md.push_str("| :--- | :--- | :--- | :--- | :--- |\n");
        for c in &bundle.controls {
            let status_badge = match c.status {
                ControlStatus::Passed => "[PASS] COMPLIANT",
                ControlStatus::Failed => "[FAIL] DEFICIENT",
                ControlStatus::NotApplicable => "[N/A] NOT APPLICABLE",
            };
            let summary = if c.findings_refs.is_empty() {
                "All automated posture tests passed without violation.".to_string()
            } else {
                c.findings_refs.join("; ")
            };
            md.push_str(&format!(
                "| **{}** | {} | `{}` | {} | {} |\n",
                c.control_id, c.title, status_badge, c.failing_findings_count, summary
            ));
        }

        md
    }

    pub fn to_csv(bundle: &AuditEvidenceBundle) -> String {
        let mut csv = String::new();
        csv.push_str("Control ID,Framework,Title,Status,Failing Findings Count,Summary\n");
        for c in &bundle.controls {
            let status_str = match c.status {
                ControlStatus::Passed => "PASSED",
                ControlStatus::Failed => "FAILED",
                ControlStatus::NotApplicable => "NOT_APPLICABLE",
            };
            let escaped_title = c.title.replace('"', "\"\"");
            let escaped_summary = c.findings_refs.join("; ").replace('"', "\"\"");
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\"\n",
                c.control_id, c.framework, escaped_title, status_str, c.failing_findings_count, escaped_summary
            ));
        }
        csv
    }
}

#[derive(Error, Debug)]
pub enum ComplianceError {
    #[error("Framework error: {0}")]
    Framework(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(String),
}

/// Executable commands accepted by UnifiedPostureAggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceCommand {
    IngestFindings(String),
    EvaluateFramework(String),
    CompileBundle { framework: String, organization: String },
    Clear,
}

/// State snapshot of the UnifiedPostureAggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStateSnapshot {
    pub total_findings: usize,
    pub top_remediations_count: usize,
    pub frameworks_evaluated: usize,
    pub findings: Vec<IngestedPostureFinding>,
}

impl CloudSecureAppEngine for UnifiedPostureAggregator {
    type Command = ComplianceCommand;
    type StateSnapshot = ComplianceStateSnapshot;
    type Error = ComplianceError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 13,
            id: "compliancesecure",
            name: "ComplianceSecure",
            pillar: "GOVERNANCE",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Executive compliance command center, top-10 breach-stopping remediation queue, and signed audit evidence exporter.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            ComplianceCommand::IngestFindings(json_str) => {
                let list: Vec<IngestedPostureFinding> = serde_json::from_str(&json_str)?;
                let count = list.len();
                self.ingest_findings(list);
                Ok(CommandReceipt {
                    command_name: "IngestFindings".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            ComplianceCommand::EvaluateFramework(fw_str) => {
                let fw = ComplianceFramework::parse_code(&fw_str)
                    .ok_or_else(|| ComplianceError::Framework(format!("Unknown framework: {}", fw_str)))?;
                let summary = self.evaluate_framework(fw);
                Ok(CommandReceipt {
                    command_name: "EvaluateFramework".into(),
                    records_affected: summary.total_controls,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(fw_str.as_bytes())),
                })
            }
            ComplianceCommand::CompileBundle { framework, organization } => {
                let fw = ComplianceFramework::parse_code(&framework)
                    .ok_or_else(|| ComplianceError::Framework(format!("Unknown framework: {}", framework)))?;
                let bundle = self.compile_bundle(fw, &organization);
                Ok(CommandReceipt {
                    command_name: "CompileBundle".into(),
                    records_affected: bundle.controls.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: bundle.manifest_sha256,
                })
            }
            ComplianceCommand::Clear => {
                let count = self.findings.len();
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
        ComplianceStateSnapshot {
            total_findings: self.findings.len(),
            top_remediations_count: self.prioritize_remediations().len(),
            frameworks_evaluated: 6,
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
                    text: f.description.clone(),
                },
            });

            results.push(SarifResult {
                rule_id: f.rule_id.clone(),
                level: match f.severity {
                    Severity::Critical | Severity::High => "error".into(),
                    Severity::Medium => "warning".into(),
                    Severity::Low => "note".into(),
                    Severity::Info => "none".into(),
                },
                message: SarifMessage {
                    text: f.evidence_detail.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.resource_id.clone(),
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
                        name: "ComplianceSecure".into(),
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
