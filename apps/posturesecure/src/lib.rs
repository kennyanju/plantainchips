use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_policy::{standard_cspm_rules, PolicyRule};
use cloudsecure_rql::RqlQuery;
use cloudsecure_types::{
    AppCatalogEntry, CloudResource, Finding, SarifArtifactLocation, SarifDriver,
    SarifLocation, SarifMessage, SarifPhysicalLocation, SarifReport, SarifResult, SarifRule,
    SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PostureError {
    #[error("Failed to parse JSON inventory payload: {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("RQL evaluation error: {0}")]
    RqlError(String),
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
}

/// Cloud resource inventory storage and query index.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudResourceInventory {
    resources: Vec<CloudResource>,
    id_index: HashMap<String, usize>,
}

impl CloudResourceInventory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads resources from a JSON array or object envelope.
    pub fn load_from_json(&mut self, json_str: &str) -> Result<usize, PostureError> {
        let parsed: Vec<CloudResource> = serde_json::from_str(json_str)?;
        let count = parsed.len();
        for res in parsed {
            self.add_resource(res);
        }
        Ok(count)
    }

    pub fn add_resource(&mut self, resource: CloudResource) {
        let idx = self.resources.len();
        self.id_index.insert(resource.id.clone(), idx);
        self.resources.push(resource);
    }

    pub fn get_resource(&self, id: &str) -> Option<&CloudResource> {
        self.id_index.get(id).and_then(|&idx| self.resources.get(idx))
    }

    pub fn resources(&self) -> &[CloudResource] {
        &self.resources
    }

    pub fn len(&self) -> usize {
        self.resources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }
}

/// Compliance evaluation and framework mapping engine.
#[derive(Debug, Clone)]
pub struct ComplianceMapper {
    rules: Vec<PolicyRule>,
}

impl Default for ComplianceMapper {
    fn default() -> Self {
        Self {
            rules: standard_cspm_rules(),
        }
    }
}

impl ComplianceMapper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn evaluate_all(&self, inventory: &CloudResourceInventory) -> Vec<Finding> {
        let mut findings = Vec::new();
        for resource in inventory.resources() {
            for rule in &self.rules {
                if let Some(finding) = rule.evaluate(resource) {
                    findings.push(finding);
                }
            }
        }
        findings
    }

    pub fn evaluate_rql(&self, inventory: &CloudResourceInventory, rql: &str) -> Result<Vec<CloudResource>, PostureError> {
        let query = RqlQuery::parse(rql).map_err(|e| PostureError::RqlError(e.to_string()))?;
        let matched = inventory
            .resources()
            .iter()
            .filter(|r| query.evaluate(r))
            .cloned()
            .collect();
        Ok(matched)
    }
}

/// Attribute-level diff between baseline and current configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeDiff {
    pub attribute_path: String,
    pub baseline_value: String,
    pub current_value: String,
}

/// Out-of-band console drift detection comparing current vs baseline state hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftRecord {
    pub resource_id: String,
    pub resource_arn: String,
    pub baseline_hash: String,
    pub current_hash: String,
    pub attribute_diffs: Vec<AttributeDiff>,
}

pub struct DriftDetector;

impl DriftDetector {
    pub fn detect_drift(
        baseline: &CloudResourceInventory,
        current: &CloudResourceInventory,
    ) -> Vec<DriftRecord> {
        let mut drift_records = Vec::new();
        for curr in current.resources() {
            if let Some(base) = baseline.get_resource(&curr.id) {
                let base_hash = base.state_hash();
                let curr_hash = curr.state_hash();
                if base_hash != curr_hash {
                    let mut diffs = Vec::new();
                    // Identify diffs across top-level state keys
                    if let (Some(b_obj), Some(c_obj)) = (base.state.as_object(), curr.state.as_object()) {
                        for (k, c_val) in c_obj {
                            if let Some(b_val) = b_obj.get(k) {
                                if b_val != c_val {
                                    diffs.push(AttributeDiff {
                                        attribute_path: format!("state.{}", k),
                                        baseline_value: b_val.to_string(),
                                        current_value: c_val.to_string(),
                                    });
                                }
                            } else {
                                diffs.push(AttributeDiff {
                                    attribute_path: format!("state.{}", k),
                                    baseline_value: "null".into(),
                                    current_value: c_val.to_string(),
                                });
                            }
                        }
                    }
                    drift_records.push(DriftRecord {
                        resource_id: curr.id.clone(),
                        resource_arn: curr.arn.clone(),
                        baseline_hash: base_hash,
                        current_hash: curr_hash,
                        attribute_diffs: diffs,
                    });
                }
            }
        }
        drift_records
    }
}

/// Serializable command events accepted by PostureSecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostureCommand {
    IngestJson(String),
    EvaluateAll,
    SuppressFinding { finding_id: String, reason: String },
    Clear,
}

/// Complete state snapshot of PostureSecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureStateSnapshot {
    pub inventory: CloudResourceInventory,
    pub findings: Vec<Finding>,
    pub suppressions: HashMap<String, String>,
}

/// Primary domain engine implementation for PostureSecure.
#[derive(Debug, Clone, Default)]
pub struct PostureEngine {
    pub inventory: CloudResourceInventory,
    pub findings: Vec<Finding>,
    pub suppressions: HashMap<String, String>,
    mapper: ComplianceMapper,
}

impl PostureEngine {
    pub fn new() -> Self {
        Self {
            inventory: CloudResourceInventory::new(),
            findings: Vec::new(),
            suppressions: HashMap::new(),
            mapper: ComplianceMapper::new(),
        }
    }
}

impl CloudSecureAppEngine for PostureEngine {
    type Command = PostureCommand;
    type StateSnapshot = PostureStateSnapshot;
    type Error = PostureError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 1,
            id: "posturesecure",
            name: "PostureSecure",
            pillar: "CSPM",
            version: "0.2.0",
            license: "MIT OR Apache-2.0",
            description: "Cloud Security Posture Management engine evaluating CIS benchmarks and multi-cloud RQL policies.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            PostureCommand::IngestJson(json) => {
                let count = self.inventory.load_from_json(&json)?;
                self.findings = self.mapper.evaluate_all(&self.inventory);
                Ok(CommandReceipt {
                    command_name: "IngestJson".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", sha2::Sha256::digest(json.as_bytes())),
                })
            }
            PostureCommand::EvaluateAll => {
                self.findings = self.mapper.evaluate_all(&self.inventory);
                Ok(CommandReceipt {
                    command_name: "EvaluateAll".into(),
                    records_affected: self.findings.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "evaluated".into(),
                })
            }
            PostureCommand::SuppressFinding { finding_id, reason } => {
                let mut found = false;
                for f in &mut self.findings {
                    if f.id == finding_id {
                        f.status = cloudsecure_types::FindingStatus::Suppressed;
                        found = true;
                    }
                }
                self.suppressions.insert(finding_id.clone(), reason);
                Ok(CommandReceipt {
                    command_name: "SuppressFinding".into(),
                    records_affected: if found { 1 } else { 0 },
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("suppressed-{}", finding_id),
                })
            }
            PostureCommand::Clear => {
                let prev_count = self.inventory.len();
                self.inventory = CloudResourceInventory::new();
                self.findings.clear();
                self.suppressions.clear();
                Ok(CommandReceipt {
                    command_name: "Clear".into(),
                    records_affected: prev_count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "empty".into(),
                })
            }
        }
    }

    fn snapshot(&self) -> Self::StateSnapshot {
        PostureStateSnapshot {
            inventory: self.inventory.clone(),
            findings: self.findings.clone(),
            suppressions: self.suppressions.clone(),
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

            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            results.push(SarifResult {
                rule_id: f.rule_id.clone(),
                level: level.into(),
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
                        name: "PostureSecure".into(),
                        version: "0.2.0".into(),
                        information_uri: "https://github.com/kennyanju/plantainchips".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
