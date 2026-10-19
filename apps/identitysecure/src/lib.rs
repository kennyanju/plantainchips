use chrono::Utc;
use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, CloudProvider, Evidence, Finding, FindingStatus, RemediationFormat,
    RemediationPatch, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Failed to parse IAM bundle JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Principal not found: '{0}'")]
    PrincipalNotFound(String),
}

/// Principal classification within cloud IAM directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalType {
    User,
    Role,
    Group,
    ServiceAccount,
}

/// IAM policy statement structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyStatement {
    pub effect: String,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
}

/// Discovered cloud IAM principal entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IamPrincipal {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub principal_type: PrincipalType,
    pub provider: CloudProvider,
    pub attached_policies: Vec<String>,
    pub inline_statements: Vec<PolicyStatement>,
    pub permission_boundary: Option<String>,
    pub last_active_days: u32,
    #[serde(default)]
    pub observed_actions: Vec<String>,
}

impl IamPrincipal {
    pub fn state_hash(&self) -> String {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(serialized.as_bytes()))
    }
}

/// Detected privilege escalation vulnerability vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationVector {
    pub vector_id: String,
    pub name: String,
    pub principal_arn: String,
    pub required_actions: Vec<String>,
    pub severity: Severity,
    pub description: String,
}

/// Granted vs. Used entitlement gap report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RightSizingReport {
    pub principal_arn: String,
    pub granted_actions_count: usize,
    pub used_actions_count: usize,
    pub unused_actions_count: usize,
    pub entitlement_gap_percentage: f32,
    pub synthesized_least_privilege_policy_json: String,
    pub remediation_hcl: String,
}

/// Evaluates IAM policy algebra and net-effective permissions.
pub struct EffectivePermissionSolver;

impl EffectivePermissionSolver {
    pub fn action_matches(pattern: &str, action: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with(":*") {
            let prefix = &pattern[..pattern.len() - 1];
            return action.starts_with(prefix);
        }
        pattern.eq_ignore_ascii_case(action)
    }

    pub fn compute_effective_actions(principal: &IamPrincipal) -> Vec<String> {
        let mut allowed = HashSet::new();
        let mut denied = HashSet::new();

        for stmt in &principal.inline_statements {
            let is_allow = stmt.effect.eq_ignore_ascii_case("Allow");
            for action in &stmt.actions {
                if is_allow {
                    allowed.insert(action.clone());
                } else {
                    denied.insert(action.clone());
                }
            }
        }

        // Attached policies representation
        for pol in &principal.attached_policies {
            if pol.eq_ignore_ascii_case("AdministratorAccess") {
                allowed.insert("*".into());
            }
        }

        allowed.retain(|a| !denied.contains(a));
        let mut res: Vec<String> = allowed.into_iter().collect();
        res.sort();
        res
    }
}

/// Scans granted permissions against known cloud IAM privilege escalation vectors.
pub struct PrivilegeEscalationDetector;

impl PrivilegeEscalationDetector {
    pub fn check_principal(principal: &IamPrincipal) -> Vec<EscalationVector> {
        let mut vectors = Vec::new();
        let actions = EffectivePermissionSolver::compute_effective_actions(principal);

        let has_action = |act: &str| -> bool {
            actions.iter().any(|pattern| EffectivePermissionSolver::action_matches(pattern, act))
        };

        // Vector 1: iam:PassRole + ec2:RunInstances
        if has_action("iam:PassRole") && has_action("ec2:RunInstances") {
            vectors.push(EscalationVector {
                vector_id: "CIEM-ESC-001".into(),
                name: "EC2 Instance Profile Role Assumption".into(),
                principal_arn: principal.arn.clone(),
                required_actions: vec!["iam:PassRole".into(), "ec2:RunInstances".into()],
                severity: Severity::Critical,
                description: "Principal can pass privileged IAM roles to newly launched EC2 instances to exfiltrate administrative credentials.".into(),
            });
        }

        // Vector 2: iam:CreatePolicyVersion
        if has_action("iam:CreatePolicyVersion") {
            vectors.push(EscalationVector {
                vector_id: "CIEM-ESC-002".into(),
                name: "IAM Policy Version Injection".into(),
                principal_arn: principal.arn.clone(),
                required_actions: vec!["iam:CreatePolicyVersion".into()],
                severity: Severity::Critical,
                description: "Principal can author a new policy version granting unrestricted '*/*' administrative permissions.".into(),
            });
        }

        // Vector 3: iam:AttachUserPolicy / iam:AttachRolePolicy
        if has_action("iam:AttachUserPolicy") || has_action("iam:AttachRolePolicy") {
            vectors.push(EscalationVector {
                vector_id: "CIEM-ESC-003".into(),
                name: "Administrative Policy Attachment".into(),
                principal_arn: principal.arn.clone(),
                required_actions: vec!["iam:AttachUserPolicy".into(), "iam:AttachRolePolicy".into()],
                severity: Severity::Critical,
                description: "Principal can attach AdministratorAccess policy directly to identity or assumed roles.".into(),
            });
        }

        // Vector 4: lambda:CreateFunction + iam:PassRole
        if has_action("lambda:CreateFunction") && has_action("iam:PassRole") {
            vectors.push(EscalationVector {
                vector_id: "CIEM-ESC-004".into(),
                name: "Serverless Execution Privilege Escalation".into(),
                principal_arn: principal.arn.clone(),
                required_actions: vec!["lambda:CreateFunction".into(), "iam:PassRole".into()],
                severity: Severity::Critical,
                description: "Principal can deploy a Lambda function executing under an overprivileged role.".into(),
            });
        }

        vectors
    }
}

/// Entitlement right-sizer comparing granted actions against 90-day CloudTrail activity.
pub struct EntitlementRightSizer;

impl EntitlementRightSizer {
    pub fn right_size(principal: &IamPrincipal) -> RightSizingReport {
        let effective_actions = EffectivePermissionSolver::compute_effective_actions(principal);
        let granted_count = if effective_actions.contains(&"*".to_string()) {
            120 // Estimated expanded wildcards count
        } else {
            effective_actions.len()
        };

        let used_actions = &principal.observed_actions;
        let used_count = used_actions.len();
        let unused_count = granted_count.saturating_sub(used_count);

        let gap_pct = if granted_count > 0 {
            (unused_count as f32 / granted_count as f32) * 100.0
        } else {
            0.0
        };

        let safe_actions = if used_actions.is_empty() {
            vec!["sts:GetCallerIdentity".to_string()]
        } else {
            used_actions.clone()
        };

        let synthesized_json = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RightSizedLeastPrivilege",
                    "Effect": "Allow",
                    "Action": safe_actions,
                    "Resource": "*"
                }
            ]
        });

        let hcl = format!(
            r#"# Right-sized least-privilege policy for {}
resource "aws_iam_policy" "{}_least_privilege" {{
  name        = "{}-least-privilege"
  description = "Synthesized least privilege policy eliminating {:.1}% unused permissions"
  policy      = jsonencode({})
}}"#,
            principal.name,
            principal.name.to_lowercase().replace('_', "-"),
            principal.name.to_lowercase().replace('_', "-"),
            gap_pct,
            serde_json::to_string_pretty(&synthesized_json).unwrap_or_default()
        );

        RightSizingReport {
            principal_arn: principal.arn.clone(),
            granted_actions_count: granted_count,
            used_actions_count: used_count,
            unused_actions_count: unused_count,
            entitlement_gap_percentage: gap_pct,
            synthesized_least_privilege_policy_json: serde_json::to_string_pretty(&synthesized_json)
                .unwrap_or_default(),
            remediation_hcl: hcl,
        }
    }
}

/// Commands accepted by IdentitySecure engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityCommand {
    LoadPrincipals(String),
    ScanAll,
    Clear,
}

/// State snapshot for IdentitySecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStateSnapshot {
    pub principals: Vec<IamPrincipal>,
    pub escalations: Vec<EscalationVector>,
    pub right_sizing: Vec<RightSizingReport>,
    pub findings: Vec<Finding>,
}

/// Main domain engine for IdentitySecure (App 04).
#[derive(Debug, Clone, Default)]
pub struct IdentityEngine {
    pub principals: Vec<IamPrincipal>,
    pub escalations: Vec<EscalationVector>,
    pub right_sizing: Vec<RightSizingReport>,
    pub findings: Vec<Finding>,
}

impl IdentityEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recompute(&mut self) {
        self.escalations.clear();
        self.right_sizing.clear();
        self.findings.clear();

        for p in &self.principals {
            let esc = PrivilegeEscalationDetector::check_principal(p);
            for e in &esc {
                let evidence = Evidence {
                    rule_id: e.vector_id.clone(),
                    target_path: format!("{}.actions", p.arn),
                    expected_value: "Least-privilege role boundaries without escalation paths".into(),
                    observed_value: format!("Escalation vector via {:?}", e.required_actions),
                    message: e.description.clone(),
                    resource_state_hash: p.state_hash(),
                };

                self.findings.push(Finding {
                    id: format!("{}-{}", e.vector_id, p.id),
                    rule_id: e.vector_id.clone(),
                    title: format!("Privilege Escalation: {}", e.name),
                    severity: e.severity,
                    status: FindingStatus::Fail,
                    provider: p.provider,
                    account_id: "aws-iam".into(),
                    region: "global".into(),
                    resource_id: p.id.clone(),
                    resource_arn: p.arn.clone(),
                    resource_type: format!("{:?}", p.principal_type),
                    framework_mappings: vec!["CIS AWS: 1.16".into(), "SOC 2: CC6.3".into(), "PCI-DSS: 7.2".into()],
                    evidence,
                    remediation: None,
                    timestamp: Utc::now(),
                });
            }
            self.escalations.extend(esc);

            let rs = EntitlementRightSizer::right_size(p);
            if rs.entitlement_gap_percentage >= 50.0 {
                let evidence = Evidence {
                    rule_id: "CIEM-GAP-001".into(),
                    target_path: format!("{}.entitlement_gap", p.arn),
                    expected_value: "Entitlement gap < 20%".into(),
                    observed_value: format!("{:.1}% unused permissions gap", rs.entitlement_gap_percentage),
                    message: format!(
                        "Principal '{}' has {} granted actions but only uses {} over 90 days.",
                        p.name, rs.granted_actions_count, rs.used_actions_count
                    ),
                    resource_state_hash: p.state_hash(),
                };

                let hcl = rs.remediation_hcl.clone();
                self.findings.push(Finding {
                    id: format!("CIEM-GAP-{}", p.id),
                    rule_id: "CIEM-GAP-001".into(),
                    title: "Overpermissive Cloud IAM Entitlement Gap".into(),
                    severity: Severity::High,
                    status: FindingStatus::Fail,
                    provider: p.provider,
                    account_id: "aws-iam".into(),
                    region: "global".into(),
                    resource_id: p.id.clone(),
                    resource_arn: p.arn.clone(),
                    resource_type: format!("{:?}", p.principal_type),
                    framework_mappings: vec!["NIST 800-53: AC-6".into(), "CIS AWS: 1.16".into()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::TerraformHcl,
                        code: hcl.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(hcl.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
            self.right_sizing.push(rs);
        }
    }
}

impl CloudSecureAppEngine for IdentityEngine {
    type Command = IdentityCommand;
    type StateSnapshot = IdentityStateSnapshot;
    type Error = IdentityError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 4,
            id: "identitysecure",
            name: "IdentitySecure",
            pillar: "IDENTITY",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "CIEM net-effective permissions solver, privilege escalation detector, and blast radius engine.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            IdentityCommand::LoadPrincipals(json_str) => {
                self.principals = serde_json::from_str(&json_str)?;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadPrincipals".into(),
                    records_affected: self.principals.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            IdentityCommand::ScanAll => {
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "ScanAll".into(),
                    records_affected: self.principals.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "scanned".into(),
                })
            }
            IdentityCommand::Clear => {
                let count = self.principals.len();
                self.principals.clear();
                self.escalations.clear();
                self.right_sizing.clear();
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
        IdentityStateSnapshot {
            principals: self.principals.clone(),
            escalations: self.escalations.clone(),
            right_sizing: self.right_sizing.clone(),
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
                        name: "IdentitySecure".into(),
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
