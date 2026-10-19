use chrono::Utc;
use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, CloudProvider, Evidence, Finding, FindingStatus, RemediationFormat,
    RemediationPatch, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ThreatError {
    #[error("Failed to parse audit log events JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Correlation failure: {0}")]
    CorrelationError(String),
}

/// Normalized Cloud Audit Event (compatible with AWS CloudTrail, GCP Audit Logs, and Azure Activity).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudAuditEvent {
    pub event_id: String,
    pub event_time: String,
    pub event_source: String,
    pub event_name: String,
    pub aws_region: Option<String>,
    pub source_ip_address: String,
    pub user_agent: Option<String>,
    #[serde(default)]
    pub user_identity: Option<AuditEventUserIdentity>,
    pub request_parameters: Option<serde_json::Value>,
    pub response_elements: Option<serde_json::Value>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventUserIdentity {
    #[serde(rename = "type")]
    pub identity_type: Option<String>,
    pub principal_id: Option<String>,
    pub arn: Option<String>,
    pub account_id: Option<String>,
    pub user_name: Option<String>,
}

impl CloudAuditEvent {
    pub fn state_hash(&self) -> String {
        let raw = format!("{}:{}:{}:{}", self.event_id, self.event_time, self.event_source, self.event_name);
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }

    pub fn principal_identifier(&self) -> String {
        if let Some(ref u) = self.user_identity {
            if let Some(ref arn) = u.arn {
                return arn.clone();
            }
            if let Some(ref user_name) = u.user_name {
                return user_name.clone();
            }
            if let Some(ref pid) = u.principal_id {
                return pid.clone();
            }
        }
        self.source_ip_address.clone()
    }
}

/// MITRE ATT&CK Cloud Technique Detection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatDetection {
    pub detection_id: String,
    pub event_id: String,
    pub rule_id: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub principal_arn: String,
    pub source_ip: String,
    pub event_time: String,
    pub evidence_detail: String,
    pub containment_action: String,
}

/// Correlated multi-stage attack incident showing kill chain progression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelatedIncident {
    pub incident_id: String,
    pub principal_arn: String,
    pub source_ip: String,
    pub start_time: String,
    pub end_time: String,
    pub tactics_observed: Vec<String>,
    pub techniques_observed: Vec<String>,
    pub event_count: usize,
    pub detections: Vec<ThreatDetection>,
    pub confidence_score: f64,
    pub status: String,
    pub recommended_containment: Vec<String>,
}

/// ThreatSecure CDR and MITRE ATT&CK Cloud correlation engine.
pub struct ThreatEngine {
    pub events: Vec<CloudAuditEvent>,
    pub detections: Vec<ThreatDetection>,
    pub incidents: Vec<CorrelatedIncident>,
    pub findings: Vec<Finding>,
}

impl Default for ThreatEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatEngine {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            detections: Vec::new(),
            incidents: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Evaluates a single cloud audit event against MITRE ATT&CK Cloud rules.
    pub fn evaluate_event(event: &CloudAuditEvent) -> Vec<ThreatDetection> {
        let mut detections = Vec::new();
        let principal = event.principal_identifier();
        let src_ip = event.source_ip_address.clone();
        let ev_time = event.event_time.clone();

        // 1. T1562.008 Impair Defenses: Disable Cloud Logs (TA0005 Defense Evasion)
        if event.event_name == "StopLogging"
            || event.event_name == "DeleteTrail"
            || event.event_name == "DeleteDetector"
            || (event.event_name == "UpdateTrail"
                && event.request_parameters.as_ref().map(|p| p.to_string()).unwrap_or_default().contains("\"isMultiRegionTrail\":false"))
        {
            let trail_name = event
                .request_parameters
                .as_ref()
                .and_then(|p| p.get("name").or_else(|| p.get("trailName")))
                .and_then(|v| v.as_str())
                .unwrap_or("arn:aws:cloudtrail:us-east-1:123456789012:trail/main");

            detections.push(ThreatDetection {
                detection_id: format!("DET-{}", event.event_id),
                event_id: event.event_id.clone(),
                rule_id: "CDR-AWS-001".into(),
                technique_id: "T1562.008".into(),
                technique_name: "Impair Defenses: Disable Cloud Logs".into(),
                tactic: "Defense Evasion".into(),
                severity: Severity::Critical,
                title: "CloudTrail Logging Disabled or Tampered".into(),
                description: format!(
                    "Adversary disabled or deleted audit trail '{}' to conceal malicious activities.",
                    trail_name
                ),
                principal_arn: principal.clone(),
                source_ip: src_ip.clone(),
                event_time: ev_time.clone(),
                evidence_detail: format!("Event '{}' executed on trail '{}'", event.event_name, trail_name),
                containment_action: format!("aws cloudtrail start-logging --name {}", trail_name),
            });
        }

        // 2. T1098.001 Account Manipulation: Additional Cloud Credentials (TA0003 Persistence)
        if event.event_name == "CreateAccessKey" {
            let target_user = event
                .request_parameters
                .as_ref()
                .and_then(|p| p.get("userName"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            detections.push(ThreatDetection {
                detection_id: format!("DET-{}", event.event_id),
                event_id: event.event_id.clone(),
                rule_id: "CDR-AWS-002".into(),
                technique_id: "T1098.001".into(),
                technique_name: "Account Manipulation: Additional Cloud Credentials".into(),
                tactic: "Persistence".into(),
                severity: Severity::High,
                title: "New IAM Long-Term Access Key Generated".into(),
                description: format!(
                    "Long-term programmatic access key created for user '{}' by principal '{}'.",
                    target_user, principal
                ),
                principal_arn: principal.clone(),
                source_ip: src_ip.clone(),
                event_time: ev_time.clone(),
                evidence_detail: format!("CreateAccessKey invoked for target user '{}'", target_user),
                containment_action: format!("aws iam update-access-key --user-name {} --status Inactive", target_user),
            });
        }

        // 3. T1098 Account Manipulation: Administrator Privilege Grant (TA0004 Privilege Escalation)
        if event.event_name == "AttachUserPolicy"
            || event.event_name == "AttachRolePolicy"
            || event.event_name == "PutUserPolicy"
            || event.event_name == "PutRolePolicy"
        {
            let params_str = event.request_parameters.as_ref().map(|p| p.to_string()).unwrap_or_default();
            if params_str.contains("AdministratorAccess") || params_str.contains("\"*\"") {
                detections.push(ThreatDetection {
                    detection_id: format!("DET-{}", event.event_id),
                    event_id: event.event_id.clone(),
                    rule_id: "CDR-AWS-003".into(),
                    technique_id: "T1098".into(),
                    technique_name: "Account Manipulation: Privilege Escalation".into(),
                    tactic: "Privilege Escalation".into(),
                    severity: Severity::Critical,
                    title: "Administrator Privileges Granted to IAM Principal".into(),
                    description: format!(
                        "Principal '{}' escalated privileges by attaching administrative policy.",
                        principal
                    ),
                    principal_arn: principal.clone(),
                    source_ip: src_ip.clone(),
                    event_time: ev_time.clone(),
                    evidence_detail: format!("Event '{}' with policy parameters '{}'", event.event_name, params_str),
                    containment_action: "aws iam put-user-policy --policy-name DenyAll --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}'".into(),
                });
            }
        }

        // 4. T1078.004 Valid Accounts: Cloud Accounts (TA0001 Initial Access)
        if event.event_name == "ConsoleLogin" {
            let mfa_used = event
                .response_elements
                .as_ref()
                .and_then(|r| r.get("ConsoleLogin"))
                .and_then(|v| v.as_str())
                == Some("Success");

            let params_str = event.request_parameters.as_ref().map(|p| p.to_string()).unwrap_or_default();
            let is_mfa_no = params_str.contains("\"MFAUsed\":\"No\"") || params_str.contains("\"mfa\":false");

            if mfa_used && is_mfa_no {
                detections.push(ThreatDetection {
                    detection_id: format!("DET-{}", event.event_id),
                    event_id: event.event_id.clone(),
                    rule_id: "CDR-AWS-004".into(),
                    technique_id: "T1078.004".into(),
                    technique_name: "Valid Accounts: Cloud Accounts".into(),
                    tactic: "Initial Access".into(),
                    severity: Severity::High,
                    title: "Console Login Succeeded Without Multi-Factor Authentication (MFA)".into(),
                    description: format!(
                        "Console session established for '{}' from '{}' without requiring MFA verification.",
                        principal, src_ip
                    ),
                    principal_arn: principal.clone(),
                    source_ip: src_ip.clone(),
                    event_time: ev_time.clone(),
                    evidence_detail: format!("ConsoleLogin from IP '{}' with MFAUsed='No'", src_ip),
                    containment_action: "aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/DenyAllExceptSelfManagement".into(),
                });
            }
        }

        // 5. T1537 Transfer Data to Cloud Account (TA0010 Exfiltration)
        if event.event_name == "ModifyImageAttribute"
            || event.event_name == "ModifySnapshotAttribute"
            || event.event_name == "PutBucketAcl"
        {
            let params_str = event.request_parameters.as_ref().map(|p| p.to_string()).unwrap_or_default();
            if params_str.contains("\"all\"") || params_str.contains("public-read") || params_str.contains("\"Group\":\"all\"") {
                detections.push(ThreatDetection {
                    detection_id: format!("DET-{}", event.event_id),
                    event_id: event.event_id.clone(),
                    rule_id: "CDR-AWS-006".into(),
                    technique_id: "T1537".into(),
                    technique_name: "Transfer Data to Cloud Account: Exfiltration".into(),
                    tactic: "Exfiltration".into(),
                    severity: Severity::Critical,
                    title: "Snapshot or Storage Object Shared Externally or Publicly".into(),
                    description: format!(
                        "Adversary modified resource permissions to permit external or global public access."
                    ),
                    principal_arn: principal.clone(),
                    source_ip: src_ip.clone(),
                    event_time: ev_time.clone(),
                    evidence_detail: format!("Event '{}' with public sharing parameters: '{}'", event.event_name, params_str),
                    containment_action: "aws ec2 modify-snapshot-attribute --attribute createVolumePermission --operation-type remove --group-names all".into(),
                });
            }
        }

        // 6. T1485 Data Destruction (TA0040 Impact)
        if event.event_name == "DeleteBucket"
            || event.event_name == "DeleteVolume"
            || event.event_name == "DeleteDBCluster"
        {
            detections.push(ThreatDetection {
                detection_id: format!("DET-{}", event.event_id),
                event_id: event.event_id.clone(),
                rule_id: "CDR-AWS-007".into(),
                technique_id: "T1485".into(),
                technique_name: "Data Destruction".into(),
                tactic: "Impact".into(),
                severity: Severity::High,
                title: "Destructive Cloud Storage or Database Deletion".into(),
                description: format!(
                    "Resource deletion event '{}' executed by principal '{}'.",
                    event.event_name, principal
                ),
                principal_arn: principal.clone(),
                source_ip: src_ip.clone(),
                event_time: ev_time.clone(),
                evidence_detail: format!("Destructive API call '{}' completed", event.event_name),
                containment_action: "aws iam put-user-policy --policy-name DenyDestructiveActions --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":[\"s3:Delete*\",\"ec2:Delete*\",\"rds:Delete*\"],\"Resource\":\"*\"}]}'".into(),
            });
        }

        detections
    }

    /// Correlates individual detections by principal into multi-stage attack incidents.
    pub fn correlate_kill_chains(detections: &[ThreatDetection]) -> Vec<CorrelatedIncident> {
        let mut grouped: HashMap<String, Vec<ThreatDetection>> = HashMap::new();
        for d in detections {
            grouped.entry(d.principal_arn.clone()).or_default().push(d.clone());
        }

        let mut incidents = Vec::new();
        for (principal, dets) in grouped {
            let mut tactics_set = BTreeMap::new();
            let mut tech_set = BTreeMap::new();
            let mut min_time = "9999-99-99".to_string();
            let mut max_time = "0000-00-00".to_string();
            let mut src_ip = "unknown".to_string();
            let mut actions = Vec::new();

            for d in &dets {
                tactics_set.insert(d.tactic.clone(), true);
                tech_set.insert(d.technique_id.clone(), true);
                if d.event_time < min_time {
                    min_time = d.event_time.clone();
                }
                if d.event_time > max_time {
                    max_time = d.event_time.clone();
                }
                src_ip = d.source_ip.clone();
                actions.push(d.containment_action.clone());
            }

            let tactics: Vec<String> = tactics_set.into_keys().collect();
            let techniques: Vec<String> = tech_set.into_keys().collect();

            // Calculate confidence score based on multi-tactic progression
            let confidence = match tactics.len() {
                0 => 0.0,
                1 => 0.65,
                2 => 0.85,
                _ => 0.98,
            };

            let inc_id = format!("INC-{}", &format!("{:x}", Sha256::digest(principal.as_bytes()))[..10]);
            incidents.push(CorrelatedIncident {
                incident_id: inc_id,
                principal_arn: principal,
                source_ip: src_ip,
                start_time: min_time,
                end_time: max_time,
                tactics_observed: tactics,
                techniques_observed: techniques,
                event_count: dets.len(),
                detections: dets,
                confidence_score: confidence,
                status: "ACTIVE".into(),
                recommended_containment: actions,
            });
        }

        // Sort by confidence score descending
        incidents.sort_by(|a, b| b.confidence_score.partial_cmp(&a.confidence_score).unwrap_or(std::cmp::Ordering::Equal));
        incidents
    }

    pub fn recompute(&mut self) {
        self.detections.clear();
        self.incidents.clear();
        self.findings.clear();

        for ev in &self.events {
            let dets = Self::evaluate_event(ev);
            for d in dets {
                self.detections.push(d.clone());

                let evidence = Evidence {
                    rule_id: d.rule_id.clone(),
                    target_path: format!("{} ({})", d.principal_arn, d.source_ip),
                    expected_value: "Compliant cloud operations without MITRE ATT&CK adversarial techniques".into(),
                    observed_value: d.evidence_detail.clone(),
                    message: d.description.clone(),
                    resource_state_hash: ev.state_hash(),
                };

                self.findings.push(Finding {
                    id: format!("{}-{}", d.rule_id, d.event_id),
                    rule_id: d.rule_id.clone(),
                    title: d.title.clone(),
                    severity: d.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "audit-stream".into(),
                    region: ev.aws_region.clone().unwrap_or_else(|| "global".into()),
                    resource_id: d.principal_arn.clone(),
                    resource_arn: d.principal_arn.clone(),
                    resource_type: "AWS::IAM::Principal".into(),
                    framework_mappings: vec![
                        format!("MITRE ATT&CK: {}", d.technique_id),
                        format!("Tactic: {}", d.tactic),
                    ],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::AwsCli,
                        code: d.containment_action.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(d.containment_action.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        self.incidents = Self::correlate_kill_chains(&self.detections);
    }
}

/// Commands accepted by the ThreatEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatCommand {
    LoadAuditEvents(String),
    Clear,
}

/// Snapshot of the ThreatEngine state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStateSnapshot {
    pub events_count: usize,
    pub detections_count: usize,
    pub incidents_count: usize,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

impl CloudSecureAppEngine for ThreatEngine {
    type Command = ThreatCommand;
    type StateSnapshot = ThreatStateSnapshot;
    type Error = ThreatError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 7,
            id: "threatsecure",
            name: "ThreatSecure",
            pillar: "CDR",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Cloud Detection and Response (CDR) engine mapping multi-cloud audit logs to MITRE ATT&CK Cloud matrices and synthesizing kill chain incidents.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            ThreatCommand::LoadAuditEvents(json_str) => {
                let events: Vec<CloudAuditEvent> = serde_json::from_str(&json_str)?;
                let count = events.len();
                self.events = events;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadAuditEvents".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            ThreatCommand::Clear => {
                let count = self.events.len();
                self.events.clear();
                self.detections.clear();
                self.incidents.clear();
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
        ThreatStateSnapshot {
            events_count: self.events.len(),
            detections_count: self.detections.len(),
            incidents_count: self.incidents.len(),
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
                help_uri: format!("https://attack.mitre.org/techniques/{}", f.rule_id),
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
                        name: "ThreatSecure".into(),
                        version: "0.1.0".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
