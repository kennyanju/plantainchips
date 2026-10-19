use chrono::{DateTime, Utc};
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
pub enum DataError {
    #[error("Failed to parse JSON datastore payload: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("Classification error: {0}")]
    ClassificationError(String),
}

/// Category of sensitive data identified during content classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClassificationCategory {
    Pii,
    Pci,
    Phi,
    Secret,
    Financial,
}

/// Supported managed and unmanaged cloud data store types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataStoreType {
    S3Bucket,
    AzureBlob,
    GcsBucket,
    RdsTable,
    SnowflakeWarehouse,
    BigQueryDataset,
}

/// Classified sensitive pattern match with mandatory redacting applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationHit {
    pub category: ClassificationCategory,
    pub rule_name: String,
    pub hit_count: usize,
    pub confidence: f32,
    pub redacted_sample: String,
    pub sha256_fingerprint: String,
}

/// Discovered cloud data asset registered in the inventory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataStore {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub store_type: DataStoreType,
    pub provider: CloudProvider,
    pub region: String,
    pub account_id: String,
    pub is_public: bool,
    pub encryption_enabled: bool,
    pub kms_key_id: Option<String>,
    pub is_shadow_copy: bool,
    pub records_count: u64,
    pub sample_data: Option<serde_json::Value>,
    #[serde(default)]
    pub classifications: Vec<ClassificationHit>,
}

impl DataStore {
    pub fn state_hash(&self) -> String {
        let serialized = serde_json::to_string(&self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// ISO/IEC 7812 Luhn checksum validator for credit card primary account numbers.
pub struct LuhnValidator;

impl LuhnValidator {
    pub fn validate(digits_str: &str) -> bool {
        let cleaned: String = digits_str.chars().filter(|c| c.is_ascii_digit()).collect();
        if cleaned.len() < 13 || cleaned.len() > 19 {
            return false;
        }

        let mut sum = 0;
        let mut double = false;
        for c in cleaned.chars().rev() {
            let mut digit = c.to_digit(10).unwrap();
            if double {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }
            sum += digit;
            double = !double;
        }
        sum % 10 == 0
    }
}

/// Mandatory redactor ensuring raw secrets and sensitive tokens never persist in memory or disk.
pub struct SecretRedactor;

impl SecretRedactor {
    pub fn redact(raw: &str) -> (String, String) {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        let fingerprint = format!("{:x}", hasher.finalize());

        let len = raw.len();
        let redacted = if len <= 8 {
            "****".to_string()
        } else {
            let prefix = &raw[..4];
            let suffix = &raw[len - 4..];
            format!("{}-****-****-{}", prefix, suffix)
        };

        (redacted, fingerprint)
    }
}

/// Linear-time scanner classifying sensitive data across text and JSON buffers.
pub struct SensitiveDataClassifier;

impl SensitiveDataClassifier {
    pub fn scan_text(text: &str) -> Vec<ClassificationHit> {
        let mut hits = Vec::new();

        // 1. AWS Access Key ID check (AKIA...)
        for token in text.split_whitespace() {
            let cleaned = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
            if cleaned.starts_with("AKIA") && cleaned.len() == 20 {
                let (redacted, fp) = SecretRedactor::redact(cleaned);
                hits.push(ClassificationHit {
                    category: ClassificationCategory::Secret,
                    rule_name: "AWS_ACCESS_KEY_ID".into(),
                    hit_count: 1,
                    confidence: 1.0,
                    redacted_sample: redacted,
                    sha256_fingerprint: fp,
                });
            }
        }

        // 2. Private Key Header check
        if text.contains("-----BEGIN PRIVATE KEY-----") || text.contains("-----BEGIN RSA PRIVATE KEY-----") {
            let (redacted, fp) = SecretRedactor::redact("PRIVATE_KEY_BLOCK");
            hits.push(ClassificationHit {
                category: ClassificationCategory::Secret,
                rule_name: "PKCS8_RSA_PRIVATE_KEY".into(),
                hit_count: 1,
                confidence: 1.0,
                redacted_sample: redacted,
                sha256_fingerprint: fp,
            });
        }

        // 3. Social Security Number check (XXX-XX-XXXX)
        for word in text.split_whitespace() {
            let cleaned = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '-');
            if cleaned.len() == 11 && cleaned.chars().nth(3) == Some('-') && cleaned.chars().nth(6) == Some('-') {
                let parts: Vec<&str> = cleaned.split('-').collect();
                if parts.len() == 3 && parts[0].len() == 3 && parts[1].len() == 2 && parts[2].len() == 4 {
                    let (redacted, fp) = SecretRedactor::redact(cleaned);
                    hits.push(ClassificationHit {
                        category: ClassificationCategory::Pii,
                        rule_name: "US_SSN_PATTERN".into(),
                        hit_count: 1,
                        confidence: 0.95,
                        redacted_sample: redacted,
                        sha256_fingerprint: fp,
                    });
                }
            }
        }

        // 4. Payment Card PAN check (Luhn verified)
        for token in text.split_whitespace() {
            let cleaned: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
            if (cleaned.len() == 15 || cleaned.len() == 16) && LuhnValidator::validate(&cleaned) {
                let (redacted, fp) = SecretRedactor::redact(&cleaned);
                hits.push(ClassificationHit {
                    category: ClassificationCategory::Pci,
                    rule_name: "PCI_CREDIT_CARD_PAN".into(),
                    hit_count: 1,
                    confidence: 0.99,
                    redacted_sample: redacted,
                    sha256_fingerprint: fp,
                });
            }
        }

        hits
    }

    pub fn scan_json(val: &serde_json::Value) -> Vec<ClassificationHit> {
        let serialized = serde_json::to_string(val).unwrap_or_default();
        Self::scan_text(&serialized)
    }
}

/// Data Detection and Response (DDR) policy evaluator.
pub struct DdrEngine;

impl DdrEngine {
    pub fn evaluate_store(store: &DataStore) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_pci = store.classifications.iter().any(|c| c.category == ClassificationCategory::Pci);
        let has_pii = store.classifications.iter().any(|c| c.category == ClassificationCategory::Pii);
        let has_secrets = store.classifications.iter().any(|c| c.category == ClassificationCategory::Secret);

        // Finding 1: Public Exposure of Sensitive Data
        if store.is_public && (has_pci || has_pii || has_secrets) {
            let evidence = Evidence {
                rule_id: "DDR-DSPM-001".into(),
                target_path: format!("{}.is_public == true", store.name),
                expected_value: "Restricted private data store".into(),
                observed_value: "Public Internet exposure with classified records".into(),
                message: format!(
                    "Data store '{}' is publicly accessible and contains sensitive records (PCI: {}, PII: {}, Secrets: {}).",
                    store.name, has_pci, has_pii, has_secrets
                ),
                resource_state_hash: store.state_hash(),
            };

            let hcl = format!(
                r#"# Revoke public exposure on {}
resource "aws_s3_bucket_public_access_block" "{}_block" {{
  bucket = "{}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}"#,
                store.name, store.name, store.name
            );

            findings.push(Finding {
                id: format!("DDR-DSPM-001-{}", store.id),
                rule_id: "DDR-DSPM-001".into(),
                title: "Publicly Exposed Sensitive Data Store".into(),
                severity: Severity::Critical,
                status: FindingStatus::Fail,
                provider: store.provider,
                account_id: store.account_id.clone(),
                region: store.region.clone(),
                resource_id: store.id.clone(),
                resource_arn: store.arn.clone(),
                resource_type: format!("{:?}", store.store_type),
                framework_mappings: vec!["PCI-DSS: 3.4".into(), "SOC 2: CC6.1".into(), "GDPR: Art 32".into()],
                evidence,
                remediation: Some(RemediationPatch {
                    format: RemediationFormat::TerraformHcl,
                    code: hcl.clone(),
                    sha256_hash: format!("{:x}", Sha256::digest(hcl.as_bytes())),
                }),
                timestamp: Utc::now(),
            });
        }

        // Finding 2: Shadow Unencrypted Copy
        if store.is_shadow_copy && !store.encryption_enabled {
            let evidence = Evidence {
                rule_id: "DDR-DSPM-002".into(),
                target_path: format!("{}.encryption_enabled == false", store.name),
                expected_value: "Encrypted at rest with KMS".into(),
                observed_value: "Unencrypted shadow staging copy".into(),
                message: format!("Data store '{}' is an unencrypted shadow replica.", store.name),
                resource_state_hash: store.state_hash(),
            };

            findings.push(Finding {
                id: format!("DDR-DSPM-002-{}", store.id),
                rule_id: "DDR-DSPM-002".into(),
                title: "Unencrypted Shadow Data Store Replica".into(),
                severity: Severity::High,
                status: FindingStatus::Fail,
                provider: store.provider,
                account_id: store.account_id.clone(),
                region: store.region.clone(),
                resource_id: store.id.clone(),
                resource_arn: store.arn.clone(),
                resource_type: format!("{:?}", store.store_type),
                framework_mappings: vec!["NIST 800-53: SC-28".into(), "HIPAA: 164.312".into()],
                evidence,
                remediation: None,
                timestamp: Utc::now(),
            });
        }

        findings
    }
}

/// Commands accepted by the DataSecure engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataCommand {
    IngestStores(String),
    ClassifyAll,
    Clear,
}

/// Snapshot of the current DataSecure state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataStateSnapshot {
    pub stores: Vec<DataStore>,
    pub findings: Vec<Finding>,
}

/// Primary domain engine implementation for DataSecure (App 02).
#[derive(Debug, Clone, Default)]
pub struct DataEngine {
    pub stores: Vec<DataStore>,
    pub findings: Vec<Finding>,
}

impl DataEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_json(&mut self, json_str: &str) -> Result<usize, DataError> {
        let mut parsed: Vec<DataStore> = serde_json::from_str(json_str)?;
        let count = parsed.len();
        for store in &mut parsed {
            if let Some(ref sample) = store.sample_data {
                store.classifications = SensitiveDataClassifier::scan_json(sample);
            }
            let ddr_findings = DdrEngine::evaluate_store(store);
            self.findings.extend(ddr_findings);
        }
        self.stores.extend(parsed);
        Ok(count)
    }
}

impl CloudSecureAppEngine for DataEngine {
    type Command = DataCommand;
    type StateSnapshot = DataStateSnapshot;
    type Error = DataError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 2,
            id: "datasecure",
            name: "DataSecure",
            pillar: "DSPM",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Data Security Posture Management and DDR engine classifying sensitive PII, PCI, and credentials.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            DataCommand::IngestStores(json) => {
                let count = self.load_from_json(&json)?;
                Ok(CommandReceipt {
                    command_name: "IngestStores".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json.as_bytes())),
                })
            }
            DataCommand::ClassifyAll => {
                for store in &mut self.stores {
                    if let Some(ref sample) = store.sample_data {
                        store.classifications = SensitiveDataClassifier::scan_json(sample);
                    }
                }
                Ok(CommandReceipt {
                    command_name: "ClassifyAll".into(),
                    records_affected: self.stores.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "classified".into(),
                })
            }
            DataCommand::Clear => {
                let count = self.stores.len();
                self.stores.clear();
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
        DataStateSnapshot {
            stores: self.stores.clone(),
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
                        name: "DataSecure".into(),
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
