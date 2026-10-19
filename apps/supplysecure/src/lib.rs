use chrono::Utc;
use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, CloudProvider, Evidence, Finding, FindingStatus, RemediationFormat,
    RemediationPatch, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SupplyError {
    #[error("Failed to parse SLSA attestation or dependency manifest JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Verification error: {0}")]
    VerificationError(String),
}

/// SLSA Subject describing the built artifact digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaSubject {
    pub name: String,
    pub digest: HashMap<String, String>,
}

/// Material or dependency resolved during build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlsaMaterial {
    pub uri: String,
    pub digest: HashMap<String, String>,
}

/// SLSA v1.0 Provenance Predicate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlsaProvenance {
    pub slsa_version: String,
    pub builder_id: String,
    pub build_type: String,
    pub subject: Vec<SlsaSubject>,
    pub source_uri: String,
    pub source_commit_sha: String,
    pub is_hermetic: bool,
    pub is_isolated: bool,
    #[serde(default)]
    pub resolved_dependencies: Vec<SlsaMaterial>,
}

impl SlsaProvenance {
    pub fn state_hash(&self) -> String {
        let raw = format!("{}:{}:{}", self.builder_id, self.source_uri, self.source_commit_sha);
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }

    pub fn compute_slsa_level(&self) -> u8 {
        if !self.is_hermetic || !self.is_isolated {
            return 2;
        }
        if self.builder_id.contains("slsa-framework/slsa-github-generator")
            || self.builder_id.contains("tekton")
            || self.builder_id.contains("google/cloud-build")
        {
            if self.source_commit_sha.len() == 40 || self.source_commit_sha.len() == 64 {
                return 3;
            }
        }
        2
    }
}

/// Cosign / Sigstore container cryptographic signature record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CosignSignatureRecord {
    pub artifact_uri: String,
    pub digest: String,
    pub is_signed: bool,
    pub signature_algorithm: Option<String>,
    pub certificate_identity: Option<String>,
    pub oidc_issuer: Option<String>,
    pub rekor_log_entry: Option<u64>,
}

impl CosignSignatureRecord {
    pub fn state_hash(&self) -> String {
        let raw = format!("{}:{}:{}", self.artifact_uri, self.digest, self.is_signed);
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }
}

/// Dependency manifest entry for supply chain typo-squatting and confusion audits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRecord {
    pub name: String,
    pub version: String,
    pub registry: String,
    pub is_internal_scope: bool,
    pub found_on_public_registry: bool,
}

/// Diagnostic violation discovered across software supply chain gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupplyChainViolation {
    pub id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub resource_id: String,
    pub evidence_detail: String,
    pub remediation_action: String,
}

/// Synthesized Kyverno admission controller policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KyvernoAdmissionPolicy {
    pub cluster_policy_yaml: String,
}

/// Core Software Supply Chain Security (SSCS) engine.
pub struct SupplyEngine {
    pub provenance_records: Vec<SlsaProvenance>,
    pub signature_records: Vec<CosignSignatureRecord>,
    pub dependencies: Vec<DependencyRecord>,
    pub findings: Vec<Finding>,
}

impl Default for SupplyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SupplyEngine {
    pub fn new() -> Self {
        Self {
            provenance_records: Vec::new>,
            signature_records: Vec::new>,
            dependencies: Vec::new>,
            findings: Vec::new>,
        }
    }

    /// Evaluates in-toto / SLSA provenance against SLSA Level 3 security requirements.
    pub fn evaluate_provenance(prov: &SlsaProvenance) -> Vec<SupplyChainViolation> {
        let mut violations = Vec::new();
        let level = prov.compute_slsa_level();
        let artifact_name = prov.subject.first().map(|s| s.name.as_str()).unwrap_or("artifact");

        if level < 3 {
            violations.push(SupplyChainViolation {
                id: format!("SLSA-LVL3-{}", artifact_name.replace('/', "-")),
                rule_id: "SLSA-001".into(),
                severity: Severity::High,
                title: "Artifact Fails SLSA Level 3 Build Provenance Requirements".into(),
                description: format!(
                    "Artifact '{}' achieved SLSA Level {}, but policy requires SLSA Level 3 with hermetic ephemeral build isolation.",
                    artifact_name, level
                ),
                resource_id: artifact_name.into(),
                evidence_detail: format!("Calculated SLSA Level {} (hermetic={}, isolated={})", level, prov.is_hermetic, prov.is_isolated),
                remediation_action: "Migrate build pipeline to SLSA Level 3 delegator generator with ephemeral hosted runners.".into(),
            });
        }

        // Check mutable tag unpinned commit references
        if prov.source_commit_sha.len() < 40 {
            violations.push(SupplyChainViolation {
                id: format!("SLSA-PIN-{}", artifact_name.replace('/', "-")),
                rule_id: "SLSA-002".into(),
                severity: Severity::High,
                title: "Build Provenance Relies on Mutable Tag Reference".into(),
                description: format!(
                    "Source commit '{}' for artifact '{}' is a mutable reference instead of a full 40-character SHA1 commit hash.",
                    prov.source_commit_sha, artifact_name
                ),
                resource_id: artifact_name.into(),
                evidence_detail: format!("source_commit_sha='{}' is not a 40/64 character hex digest", prov.source_commit_sha),
                remediation_action: "Pin build triggers to immutable git commit SHA hashes rather than mutable branch/tag references.".into(),
            });
        }

        violations
    }

    /// Evaluates Cosign cryptographic container image signatures.
    pub fn evaluate_signature(sig: &CosignSignatureRecord) -> Vec<SupplyChainViolation> {
        let mut violations = Vec::new();

        if !sig.is_signed {
            violations.push(SupplyChainViolation {
                id: format!("COSIGN-UNSIGNED-{}", sig.artifact_uri.replace('/', "-")),
                rule_id: "COSIGN-001".into(),
                severity: Severity::Critical,
                title: "Container Image Artifact Unsigned".into(),
                description: format!(
                    "Container image '{}' ({}) lacks a verified Cosign cryptographic signature.",
                    sig.artifact_uri, sig.digest
                ),
                resource_id: sig.artifact_uri.clone(),
                evidence_detail: "is_signed=false".into(),
                remediation_action: format!("cosign sign --key k8s://cosign-keys/signing-key {}", sig.artifact_uri),
            });
        } else if sig.rekor_log_entry.is_none() {
            violations.push(SupplyChainViolation {
                id: format!("COSIGN-NOREKOR-{}", sig.artifact_uri.replace('/', "-")),
                rule_id: "COSIGN-002".into(),
                severity: Severity::High,
                title: "Signature Lacks Sigstore Rekor Transparency Log Entry".into(),
                description: format!(
                    "Image '{}' has signature but lacks non-repudiation proof in Rekor public transparency log.",
                    sig.artifact_uri
                ),
                resource_id: sig.artifact_uri.clone(),
                evidence_detail: "rekor_log_entry=null".into(),
                remediation_action: "Sign image with keyless Sigstore workflow to guarantee public transparency log inclusion.".into(),
            });
        }

        violations
    }

    /// Evaluates software package manifests for dependency confusion and typo-squatting.
    pub fn evaluate_dependency(dep: &DependencyRecord) -> Vec<SupplyChainViolation> {
        let mut violations = Vec::new();

        // 1. Dependency Confusion (DEP-CONF-001)
        if dep.is_internal_scope && dep.found_on_public_registry {
            violations.push(SupplyChainViolation {
                id: format!("DEP-CONF-{}", dep.name.replace('/', "-")),
                rule_id: "DEP-CONF-001".into(),
                severity: Severity::Critical,
                title: "Dependency Confusion Vulnerability on Internal Scoped Package".into(),
                description: format!(
                    "Internal package '{}' was detected on public registry '{}'. Adversary can publish higher version to achieve remote code execution.",
                    dep.name, dep.registry
                ),
                resource_id: dep.name.clone(),
                evidence_detail: format!("is_internal_scope=true and found_on_public_registry=true for '{}'", dep.name),
                remediation_action: format!("Claim and reserve package '{}' on public {} registry or enforce scoped registry configuration.", dep.name, dep.registry),
            });
        }

        // 2. Typo-Squatting Detection (TYPO-SQUAT-001)
        let popular_targets = ["lodash", "lodash-es", "requests", "express", "react", "axios", "chalk", "urllib3"];
        for target in popular_targets {
            let dist = damerau_levenshtein_distance(&dep.name, target);
            if dist == 1 && dep.name != target {
                violations.push(SupplyChainViolation {
                    id: format!("TYPO-{}-{}", dep.name, target),
                    rule_id: "TYPO-SQUAT-001".into(),
                    severity: Severity::High,
                    title: format!("Potential Typo-Squatting Package Mimicking '{}'", target),
                    description: format!(
                        "Package '{}' has an edit distance of 1 from popular package '{}', indicating a high risk of typo-squatting malware.",
                        dep.name, target
                    ),
                    resource_id: dep.name.clone(),
                    evidence_detail: format!("damerau_levenshtein_distance({}, {}) == 1", dep.name, target),
                    remediation_action: format!("Audit and replace suspicious package '{}' with legitimate library '{}'.", dep.name, target),
                });
            }
        }

        violations
    }

    /// Synthesizes Kyverno ClusterPolicy YAML enforcing signature and SLSA admission control.
    pub fn synthesize_admission_policy() -> KyvernoAdmissionPolicy {
        let yaml = r#"apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-cosign-and-slsa-level3
  annotations:
    policies.kyverno.io/title: Verify Image Signatures and SLSA Provenance
    policies.kyverno.io/category: Software Supply Chain Security
spec:
  validationFailureAction: Enforce
  background: false
  rules:
  - name: verify-cosign-signature
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "registry.internal.net/*"
      attestors:
      - entries:
        - keyless:
            issuer: "https://token.actions.githubusercontent.com"
            subject: "https://github.com/my-org/*"
  - name: verify-slsa-level3-attestation
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "registry.internal.net/*"
      attestations:
      - predicateType: "https://slsa.dev/provenance/v1"
        conditions:
        - all:
          - key: "{{ builder.id }}"
            operator: Equals
            value: "https://github.com/slsa-framework/slsa-github-generator/*"
"#;
        KyvernoAdmissionPolicy {
            cluster_policy_yaml: yaml.to_string(),
        }
    }

    pub fn recompute(&mut self) {
        self.findings.clear();

        for prov in &self.provenance_records {
            for v in Self::evaluate_provenance(prov) {
                let evidence = Evidence {
                    rule_id: v.rule_id.clone(),
                    target_path: format!("slsa:{}", v.resource_id),
                    expected_value: "SLSA Level 3 compliant provenance with immutable pinned commit".into(),
                    observed_value: v.evidence_detail.clone(),
                    message: v.description.clone(),
                    resource_state_hash: prov.state_hash(),
                };

                self.findings.push(Finding {
                    id: v.id.clone(),
                    rule_id: v.rule_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "build-pipeline".into(),
                    region: "global".into(),
                    resource_id: v.resource_id.clone(),
                    resource_arn: format!("arn:cloudsecure:supply:artifact/{}", v.resource_id),
                    resource_type: "SupplyChain::SLSA::Provenance".into(),
                    framework_mappings: vec!["SLSA Specification v1.0".into(), "NIST SSDF SP 800-218".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::Other("slsa-policy".into()),
                        code: v.remediation_action.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(v.remediation_action.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        for sig in &self.signature_records {
            for v in Self::evaluate_signature(sig) {
                let evidence = Evidence {
                    rule_id: v.rule_id.clone(),
                    target_path: format!("container:{}", v.resource_id),
                    expected_value: "Cryptographically signed container image with Rekor transparency entry".into(),
                    observed_value: v.evidence_detail.clone(),
                    message: v.description.clone(),
                    resource_state_hash: sig.state_hash(),
                };

                self.findings.push(Finding {
                    id: v.id.clone(),
                    rule_id: v.rule_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "container-registry".into(),
                    region: "global".into(),
                    resource_id: v.resource_id.clone(),
                    resource_arn: format!("arn:cloudsecure:supply:image/{}", v.resource_id),
                    resource_type: "SupplyChain::Cosign::Signature".into(),
                    framework_mappings: vec!["Sigstore Cosign Standard".into(), "CIS Software Supply Chain 1.0".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::Other("cosign-cli".into()),
                        code: v.remediation_action.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(v.remediation_action.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        for dep in &self.dependencies {
            for v in Self::evaluate_dependency(dep) {
                let state_hash = format!("{:x}", Sha256::digest(format!("{}:{}", dep.name, dep.version).as_bytes()));
                let evidence = Evidence {
                    rule_id: v.rule_id.clone(),
                    target_path: format!("dependency:{}", v.resource_id),
                    expected_value: "Secure dependency without naming conflicts or typo-squatting".into(),
                    observed_value: v.evidence_detail.clone(),
                    message: v.description.clone(),
                    resource_state_hash: state_hash,
                };

                self.findings.push(Finding {
                    id: v.id.clone(),
                    rule_id: v.rule_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "package-registry".into(),
                    region: "global".into(),
                    resource_id: v.resource_id.clone(),
                    resource_arn: format!("arn:cloudsecure:supply:package/{}", v.resource_id),
                    resource_type: "SupplyChain::Package::Dependency".into(),
                    framework_mappings: vec!["OWASP Top 10 Software Component Risks".into(), "NIST SP 800-218".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::Other("package-lock".into()),
                        code: v.remediation_action.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(v.remediation_action.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }
    }
}

/// Helper function computing Damerau-Levenshtein distance between two strings.
pub fn damerau_levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut dp = vec![vec![0; n + 1]; m + 1];

    for i in 0..=m {
        dp[i][0] = i;
    }
    for j in 0..=n {
        dp[0][j] = j;
    }

    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);

            if i > 1 && j > 1 && a_chars[i - 1] == b_chars[j - 2] && a_chars[i - 2] == b_chars[j - 1] {
                dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + 1);
            }
        }
    }

    dp[m][n]
}

/// Helper function computing Levenshtein distance between two strings.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    damerau_levenshtein_distance(a, b)
}

/// Commands accepted by the SupplyEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SupplyCommand {
    VerifyProvenance(String),
    VerifySignatures(String),
    ScanDependencies(String),
    Clear,
}

/// Snapshot of the SupplyEngine state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyStateSnapshot {
    pub provenance_count: usize,
    pub signatures_count: usize,
    pub dependencies_count: usize,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

impl CloudSecureAppEngine for SupplyEngine {
    type Command = SupplyCommand;
    type StateSnapshot = SupplyStateSnapshot;
    type Error = SupplyError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 11,
            id: "supplysecure",
            name: "SupplySecure",
            pillar: "SSCS",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Software Supply Chain Security (SSCS) verifying SLSA Level 3 provenance, Cosign cryptographic signatures, and dependency confusion vulnerabilities.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            SupplyCommand::VerifyProvenance(json_str) => {
                let records: Vec<SlsaProvenance> = serde_json::from_str(&json_str)?;
                let count = records.len();
                self.provenance_records = records;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "VerifyProvenance".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            SupplyCommand::VerifySignatures(json_str) => {
                let records: Vec<CosignSignatureRecord> = serde_json::from_str(&json_str)?;
                let count = records.len();
                self.signature_records = records;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "VerifySignatures".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            SupplyCommand::ScanDependencies(json_str) => {
                let records: Vec<DependencyRecord> = serde_json::from_str(&json_str)?;
                let count = records.len();
                self.dependencies = records;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "ScanDependencies".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            SupplyCommand::Clear => {
                let count = self.provenance_records.len() + self.signature_records.len() + self.dependencies.len();
                self.provenance_records.clear();
                self.signature_records.clear();
                self.dependencies.clear();
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
        SupplyStateSnapshot {
            provenance_count: self.provenance_records.len(),
            signatures_count: self.signature_records.len(),
            dependencies_count: self.dependencies.len(),
            findings_count: self.findings.len(),
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
                    text: f.title.clone(),
                },
                help_uri: format!("https://slsa.dev/spec/v1.0/"),
            });

            results.push(SarifResult {
                rule_id: f.rule_id.clone(),
                level: match f.severity {
                    Severity::Critical => "error".into(),
                    Severity::High => "error".into(),
                    Severity::Medium => "warning".into(),
                    Severity::Low => "note".into(),
                    Severity::Informational => "none".into(),
                },
                message: SarifMessage {
                    text: f.evidence.message.clone(),
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
                        name: "SupplySecure".into(),
                        version: "0.1.0".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
