use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Supported cloud infrastructure providers and runtimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    Aws,
    Azure,
    Gcp,
    Kubernetes,
    Oci,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "aws"),
            Self::Azure => write!(f, "azure"),
            Self::Gcp => write!(f, "gcp"),
            Self::Kubernetes => write!(f, "k8s"),
            Self::Oci => write!(f, "oci"),
        }
    }
}

/// Normalized risk severity rating adhering to CVSS v3.1 / CCSS mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Non-color visual glyph ensuring accessibility without relying on color alone.
    pub fn glyph(&self) -> &'static str {
        match self {
            Self::Critical => "[!]",
            Self::High => "[/!\\]",
            Self::Medium => "[<>]",
            Self::Low => "[i]",
            Self::Info => "[*]",
        }
    }
}

/// Canonical cloud resource representation ingested from provider inventory APIs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudResource {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub provider: CloudProvider,
    pub account_id: String,
    pub region: String,
    pub service: String,
    pub resource_type: String,
    pub state: serde_json::Value,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

impl CloudResource {
    /// Computes deterministic SHA-256 fingerprint of the resource state payload.
    pub fn state_hash(&self) -> String {
        let serialized = serde_json::to_string(&self.state).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Audit verification evidence capturing observed state paths and evaluated invariants.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub rule_id: String,
    pub target_path: String,
    pub expected_value: String,
    pub observed_value: String,
    pub message: String,
    pub resource_state_hash: String,
}

/// Remediating patch artifact requiring two-step human approval before application.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationPatch {
    pub format: RemediationFormat,
    pub code: String,
    pub sha256_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationFormat {
    TerraformHcl,
    AwsCli,
    AzureCli,
    GcloudCli,
    ShellScript,
}

/// Finding status indicating policy evaluation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FindingStatus {
    Pass,
    Fail,
    Error,
    NotApplicable,
}

/// Concrete security posture finding produced by evaluating a policy against a resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub provider: CloudProvider,
    pub account_id: String,
    pub region: String,
    pub resource_id: String,
    pub resource_arn: String,
    pub resource_type: String,
    pub framework_mappings: Vec<String>,
    pub evidence: Evidence,
    pub remediation: Option<RemediationPatch>,
    pub timestamp: DateTime<Utc>,
}

/// Standard compliance framework identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceFramework {
    CisAws30,
    CisAzure21,
    CisGcp20,
    Nist80053Rev5,
    Soc2Type2,
    PciDss40,
    Hipaa,
    Gdpr,
}

/// Metadata entry identifying an application within the CloudSecure catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppCatalogEntry {
    pub index: u8,
    pub id: &'static str,
    pub name: &'static str,
    pub pillar: &'static str,
    pub version: &'static str,
    pub license: &'static str,
    pub description: &'static str,
}

/// Minimal OASIS SARIF 2.1.0 report container for CI/CD security tool interoperability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}
