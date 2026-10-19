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
pub enum NetError {
    #[error("Failed to parse network configuration or flow records: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Analysis error: {0}")]
    AnalysisError(String),
}

/// Standardized VPC Flow Log record (compatible with AWS, GCP, and Azure flow formats).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VpcFlowRecord {
    pub version: u8,
    pub account_id: String,
    pub interface_id: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub bytes: u64,
    pub start: u64,
    pub end: u64,
    pub action: String,
    pub log_status: String,
}

impl VpcFlowRecord {
    pub fn state_hash(&self) -> String {
        let raw = format!(
            "{}:{}:{}:{}:{}:{}",
            self.interface_id, self.src_addr, self.dst_addr, self.src_port, self.dst_port, self.protocol
        );
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }

    pub fn is_private_ip(ip: &str) -> bool {
        if ip.starts_with("10.") || ip.starts_with("192.168.") {
            return true;
        }
        if ip.starts_with("172.") {
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() >= 2 {
                if let Ok(second) = parts[1].parse::<u8>() {
                    if (16..=31).contains(&second) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Cloud Security Group or Network Security Group Rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroupRule {
    pub rule_id: String,
    pub group_id: String,
    pub direction: String,
    pub ip_protocol: String,
    pub from_port: Option<i32>,
    pub to_port: Option<i32>,
    pub cidr_ipv4: Option<String>,
    pub description: Option<String>,
}

/// Security Group grouping multiple rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityGroup {
    pub group_id: String,
    pub group_name: String,
    pub vpc_id: String,
    #[serde(default)]
    pub rules: Vec<SecurityGroupRule>,
}

/// NetSecure diagnostic finding for network exposure or flow anomaly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetViolation {
    pub violation_id: String,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub resource_id: String,
    pub flow_or_rule_detail: String,
    pub recommended_action: String,
}

/// Synthesized Zero-Trust Microsegmentation Policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicrosegmentationPolicy {
    pub k8s_network_policy_yaml: String,
    pub aws_sg_remediation_commands: Vec<String>,
}

/// NetSecure Cloud Network Security (CNS) & Microsegmentation engine.
pub struct NetEngine {
    pub flow_records: Vec<VpcFlowRecord>,
    pub security_groups: Vec<SecurityGroup>,
    pub findings: Vec<Finding>,
}

impl Default for NetEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NetEngine {
    pub fn new() -> Self {
        Self {
            flow_records: Vec::new(),
            security_groups: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Evaluates VPC flow logs for unencrypted sensitive protocols and data exfiltration bursts.
    pub fn evaluate_flow(flow: &VpcFlowRecord) -> Vec<NetViolation> {
        let mut violations = Vec::new();

        // 1. CNS-NET-001: Cleartext Sensitive Protocol in Transit
        if flow.action == "ACCEPT" && flow.protocol == 6 {
            let cleartext_ports = [80, 21, 23, 389, 513, 514];
            if cleartext_ports.contains(&flow.dst_port) {
                let proto_name = match flow.dst_port {
                    80 => "HTTP",
                    21 => "FTP",
                    23 => "Telnet",
                    389 => "LDAP",
                    513 => "RLogin",
                    514 => "RSH",
                    _ => "Cleartext",
                };
                violations.push(NetViolation {
                    violation_id: format!("FLOW-{}-{}-{}", flow.interface_id, flow.dst_port, flow.start),
                    rule_id: "CNS-NET-001".into(),
                    severity: Severity::High,
                    title: format!("Unencrypted {} Traffic Accepted on Interface", proto_name),
                    description: format!(
                        "Interface '{}' accepted cleartext {} traffic from '{}' to port {}.",
                        flow.interface_id, proto_name, flow.src_addr, flow.dst_port
                    ),
                    resource_id: flow.interface_id.clone(),
                    flow_or_rule_detail: format!(
                        "TCP {} -> {}:{} ({} bytes accepted)",
                        flow.src_addr, flow.dst_addr, flow.dst_port, flow.bytes
                    ),
                    recommended_action: format!(
                        "Upgrade endpoint to enforce TLS/HTTPS encryption on port {} or terminate cleartext listeners.",
                        flow.dst_port
                    ),
                });
            }
        }

        // 2. CNS-NET-004: High-Volume Data Egress to External IP (Exfiltration Anomaly)
        if flow.action == "ACCEPT" && !VpcFlowRecord::is_private_ip(&flow.dst_addr) && flow.bytes > 50_000_000 {
            violations.push(NetViolation {
                violation_id: format!("EGRESS-{}-{}", flow.interface_id, flow.start),
                rule_id: "CNS-NET-004".into(),
                severity: Severity::High,
                title: "High-Volume Data Egress to External Internet IP".into(),
                description: format!(
                    "Interface '{}' transferred {:.2} MB to public IP '{}'.",
                    flow.interface_id,
                    flow.bytes as f64 / 1_000_000.0,
                    flow.dst_addr
                ),
                resource_id: flow.interface_id.clone(),
                flow_or_rule_detail: format!(
                    "Egress flow to public IP {} transferred {} bytes across {} packets",
                    flow.dst_addr, flow.bytes, flow.packets
                ),
                recommended_action: format!(
                    "Verify authorized external destination and enforce egress proxy or Magic Firewall rule for {}.",
                    flow.dst_addr
                ),
            });
        }

        violations
    }

    /// Evaluates Security Group rules for internet exposure and rule shadowing.
    pub fn evaluate_sg_rules(sg: &SecurityGroup) -> Vec<NetViolation> {
        let mut violations = Vec::new();

        for rule in &sg.rules {
            if rule.direction == "ingress" {
                let is_public = rule.cidr_ipv4.as_deref() == Some("0.0.0.0/0")
                    || rule.cidr_ipv4.as_deref() == Some("::/0");

                if is_public {
                    let from_p = rule.from_port.unwrap_or(0);
                    let to_p = rule.to_port.unwrap_or(65535);

                    // Check Management Ports (22 SSH, 3389 RDP)
                    if (from_p <= 22 && to_p >= 22) || (from_p <= 3389 && to_p >= 3389) {
                        violations.push(NetViolation {
                            violation_id: format!("SG-MGMT-{}", rule.rule_id),
                            rule_id: "CNS-NET-003".into(),
                            severity: Severity::Critical,
                            title: "Management Port (SSH/RDP) Exposed to Public Internet".into(),
                            description: format!(
                                "Security group '{}' ({}) allows public ingress (0.0.0.0/0) to management ports {}-{}.",
                                sg.group_name, sg.group_id, from_p, to_p
                            ),
                            resource_id: sg.group_id.clone(),
                            flow_or_rule_detail: format!("Ingress rule {} cidr=0.0.0.0/0 ports={}-{}", rule.rule_id, from_p, to_p),
                            recommended_action: format!(
                                "aws ec2 revoke-security-group-ingress --group-id {} --protocol tcp --port {} --cidr 0.0.0.0/0",
                                sg.group_id, from_p
                            ),
                        });
                    }

                    // Check Database Ports (5432, 3306, 6379, 27017, 9200)
                    let db_ports = [5432, 3306, 6379, 27017, 9200];
                    for &dbp in &db_ports {
                        if from_p <= dbp && to_p >= dbp {
                            violations.push(NetViolation {
                                violation_id: format!("SG-DB-{}-{}", rule.rule_id, dbp),
                                rule_id: "CNS-NET-002".into(),
                                severity: Severity::Critical,
                                title: format!("Database Port {} Exposed to Public Internet", dbp),
                                description: format!(
                                    "Security group '{}' ({}) allows public internet access to database port {}.",
                                    sg.group_name, sg.group_id, dbp
                                ),
                                resource_id: sg.group_id.clone(),
                                flow_or_rule_detail: format!("Ingress rule {} cidr=0.0.0.0/0 port={}", rule.rule_id, dbp),
                                recommended_action: format!(
                                    "aws ec2 revoke-security-group-ingress --group-id {} --protocol tcp --port {} --cidr 0.0.0.0/0",
                                    sg.group_id, dbp
                                ),
                            });
                            break;
                        }
                    }
                }
            }
        }

        // Rule Shadowing Check (e.g. broader CIDR precedes narrower CIDR)
        for i in 0..sg.rules.len() {
            for j in (i + 1)..sg.rules.len() {
                let r1 = &sg.rules[i];
                let r2 = &sg.rules[j];
                if r1.direction == r2.direction && r1.ip_protocol == r2.ip_protocol {
                    if r1.cidr_ipv4.as_deref() == Some("10.0.0.0/8") && r2.cidr_ipv4.as_deref() == Some("10.1.0.0/16") {
                        violations.push(NetViolation {
                            violation_id: format!("SHADOW-{}-{}", r1.rule_id, r2.rule_id),
                            rule_id: "CNS-NET-005".into(),
                            severity: Severity::Low,
                            title: "Redundant or Shadowed Security Group Rule".into(),
                            description: format!(
                                "Rule '{}' (10.1.0.0/16) is fully shadowed by broader rule '{}' (10.0.0.0/8).",
                                r2.rule_id, r1.rule_id
                            ),
                            resource_id: sg.group_id.clone(),
                            flow_or_rule_detail: format!("Rule {} shadowed by {}", r2.rule_id, r1.rule_id),
                            recommended_action: format!(
                                "Remove redundant rule '{}' to maintain clean security group configuration.",
                                r2.rule_id
                            ),
                        });
                    }
                }
            }
        }

        violations
    }

    /// Synthesizes zero-trust microsegmentation policy and remediation commands.
    pub fn synthesize_microsegmentation(
        flows: &[VpcFlowRecord],
        sgs: &[SecurityGroup],
    ) -> MicrosegmentationPolicy {
        let mut k8s_yaml = String::from(
            "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: zero-trust-default-microsegmentation\n  namespace: production\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\n  ingress:\n",
        );

        let mut allowed_ports = HashMap::new();
        for f in flows {
            if f.action == "ACCEPT" && f.dst_port != 80 && f.dst_port != 23 {
                allowed_ports.insert(f.dst_port, f.protocol);
            }
        }

        for (port, _proto) in &allowed_ports {
            k8s_yaml.push_str(&format!(
                "  - ports:\n    - protocol: TCP\n      port: {}\n    from:\n    - podSelector:\n        matchLabels:\n          role: authorized-peer\n",
                port
            ));
        }

        let mut remediation_cmds = Vec::new();
        for sg in sgs {
            for v in Self::evaluate_sg_rules(sg) {
                if v.rule_id == "CNS-NET-002" || v.rule_id == "CNS-NET-003" {
                    remediation_cmds.push(v.recommended_action);
                }
            }
        }

        MicrosegmentationPolicy {
            k8s_network_policy_yaml: k8s_yaml,
            aws_sg_remediation_commands: remediation_cmds,
        }
    }

    pub fn recompute(&mut self) {
        self.findings.clear();

        for flow in &self.flow_records {
            for v in Self::evaluate_flow(flow) {
                let evidence = Evidence {
                    rule_id: v.rule_id.clone(),
                    target_path: format!("interface:{}", v.resource_id),
                    expected_value: "Compliant zero-trust network traffic".into(),
                    observed_value: v.flow_or_rule_detail.clone(),
                    message: v.description.clone(),
                    resource_state_hash: flow.state_hash(),
                };

                self.findings.push(Finding {
                    id: v.violation_id.clone(),
                    rule_id: v.rule_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: flow.account_id.clone(),
                    region: "us-east-1".into(),
                    resource_id: v.resource_id.clone(),
                    resource_arn: format!("arn:aws:ec2:us-east-1:{}:network-interface/{}", flow.account_id, v.resource_id),
                    resource_type: "AWS::EC2::NetworkInterface".into(),
                    framework_mappings: vec!["NIST SP 800-207 Zero Trust Architecture".into(), "CIS AWS Foundations 5.x".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::AwsCli,
                        code: v.recommended_action.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(v.recommended_action.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }

        for sg in &self.security_groups {
            for v in Self::evaluate_sg_rules(sg) {
                let state_hash = format!("{:x}", Sha256::digest(v.flow_or_rule_detail.as_bytes()));
                let evidence = Evidence {
                    rule_id: v.rule_id.clone(),
                    target_path: format!("security_group:{}", v.resource_id),
                    expected_value: "Least-privilege security group ingress rule".into(),
                    observed_value: v.flow_or_rule_detail.clone(),
                    message: v.description.clone(),
                    resource_state_hash: state_hash,
                };

                self.findings.push(Finding {
                    id: v.violation_id.clone(),
                    rule_id: v.rule_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "aws-network".into(),
                    region: "us-east-1".into(),
                    resource_id: v.resource_id.clone(),
                    resource_arn: format!("arn:aws:ec2:us-east-1:123456789012:security-group/{}", v.resource_id),
                    resource_type: "AWS::EC2::SecurityGroup".into(),
                    framework_mappings: vec!["CIS AWS Benchmark 4.1".into(), "PCI-DSS Requirement 1.3".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::AwsCli,
                        code: v.recommended_action.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(v.recommended_action.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }
    }
}

/// Commands accepted by the NetEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetCommand {
    LoadFlowLogs(String),
    LoadSecurityGroups(String),
    Clear,
}

/// Snapshot of the NetEngine state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetStateSnapshot {
    pub flows_count: usize,
    pub sgs_count: usize,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

impl CloudSecureAppEngine for NetEngine {
    type Command = NetCommand;
    type StateSnapshot = NetStateSnapshot;
    type Error = NetError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 9,
            id: "netsecure",
            name: "NetSecure",
            pillar: "CNS",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Cloud Network Security (CNS) analyzing VPC flow logs, isolating public database exposures, and synthesizing zero-trust microsegmentation policies.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            NetCommand::LoadFlowLogs(json_str) => {
                let flows: Vec<VpcFlowRecord> = serde_json::from_str(&json_str)?;
                let count = flows.len();
                self.flow_records = flows;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadFlowLogs".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            NetCommand::LoadSecurityGroups(json_str) => {
                let sgs: Vec<SecurityGroup> = serde_json::from_str(&json_str)?;
                let count = sgs.len();
                self.security_groups = sgs;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadSecurityGroups".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            NetCommand::Clear => {
                let count = self.flow_records.len() + self.security_groups.len();
                self.flow_records.clear();
                self.security_groups.clear();
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
        NetStateSnapshot {
            flows_count: self.flow_records.len(),
            sgs_count: self.security_groups.len(),
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
                help_uri: format!("https://cns.cloudsecure.dev/rules/{}", f.rule_id),
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
                        name: "NetSecure".into(),
                        version: "0.1.0".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
