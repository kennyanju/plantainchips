//! PolicySecure: Unified RQL and Policy-as-Code Studio Engine
//!
//! Interactive parser, formatter, static type-checker, and explain-plan profiler
//! for all 5 CloudSecure RQL query families (config, network, event, iam, data).
//! Authors, validates, unit-tests, and packages custom YAML/JSON policy packs with
//! pass/fail test fixtures, severity scoring, and compliance control mappings.

use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_rql::{CloudResource, Predicate, ResourceFamily, RqlQuery};
use cloudsecure_types::{
    AppCatalogEntry, CloudProvider, Finding, SarifArtifactLocation, SarifDriver, SarifLocation,
    SarifMessage, SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool,
    Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// RQL query family enumeration for PolicySecure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyFamily {
    Config,
    Network,
    Event,
    Iam,
    Data,
    Ai,
}

impl PolicyFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "Config",
            Self::Network => "Network",
            Self::Event => "Event",
            Self::Iam => "Iam",
            Self::Data => "Data",
            Self::Ai => "Ai",
        }
    }
}

/// A policy-as-code rule with embedded positive and negative test fixtures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub family: String,
    pub severity: Severity,
    pub rql_query: String,
    pub description: String,
    pub framework_controls: Vec<String>,
    pub remediation: String,
    #[serde(default)]
    pub pass_fixtures: Vec<serde_json::Value>,
    #[serde(default)]
    pub fail_fixtures: Vec<serde_json::Value>,
}

impl PolicyRule {
    pub fn state_hash(&self) -> String {
        let raw = format!("{}:{}:{}:{}", self.id, self.family, self.severity.as_str(), self.rql_query);
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }
}

/// Bundled policy pack containing metadata and a collection of security rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPack {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub rules: Vec<PolicyRule>,
}

impl PolicyPack {
    pub fn state_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}:{}:{}", self.name, self.version, self.author).as_bytes());
        for rule in &self.rules {
            hasher.update(rule.state_hash().as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

/// Node in the RQL AST explain plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RqlExplainNode {
    pub node_type: String,
    pub target: String,
    pub expression: String,
    pub estimated_cost_ms: f64,
    pub children: Vec<RqlExplainNode>,
}

/// Detailed execution explain plan for an RQL query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RqlExplainPlan {
    pub raw_query: String,
    pub family: String,
    pub is_valid: bool,
    pub parse_time_us: u64,
    pub ast_root: Option<RqlExplainNode>,
    pub validation_errors: Vec<String>,
    pub autocomplete_suggestions: Vec<String>,
}

/// Outcome of running positive and negative test fixtures against a rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleTestOutcome {
    pub rule_id: String,
    pub rule_name: String,
    pub pass_fixtures_passed: usize,
    pub pass_fixtures_total: usize,
    pub fail_fixtures_passed: usize,
    pub fail_fixtures_total: usize,
    pub is_success: bool,
    pub failure_details: Vec<String>,
}

/// Summary report of unit tests executed across an entire policy pack.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPackTestReport {
    pub pack_name: String,
    pub pack_version: String,
    pub total_rules: usize,
    pub passed_rules: usize,
    pub failed_rules: usize,
    pub results: Vec<RuleTestOutcome>,
    pub execution_duration_ms: f64,
}

/// Validation report assessing syntax, controls, and schema compliance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPackValidationReport {
    pub pack_name: String,
    pub is_valid: bool,
    pub rule_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Core PolicySecure Engine managing RQL IDE and Policy-as-Code testing.
pub struct PolicySecureEngine {
    pub active_pack: Option<PolicyPack>,
    pub test_history: Vec<PolicyPackTestReport>,
    pub last_explain_plan: Option<RqlExplainPlan>,
}

impl Default for PolicySecureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicySecureEngine {
    pub fn new() -> Self {
        Self {
            active_pack: None,
            test_history: Vec::new(),
            last_explain_plan: None,
        }
    }

    /// Parses an RQL query and synthesizes an AST explain plan with cost estimation.
    pub fn explain_query(query_str: &str) -> RqlExplainPlan {
        let start = std::time::Instant::now();
        let trimmed = query_str.trim();

        match RqlQuery::parse(trimmed) {
            Ok(parsed) => {
                let parse_time = start.elapsed().as_micros() as u64;
                let family_name = match parsed.family {
                    ResourceFamily::Config => "Config",
                    ResourceFamily::Iam => "Iam",
                    ResourceFamily::Event => "Event",
                    ResourceFamily::Data => "Data",
                    ResourceFamily::Network => "Network",
                    ResourceFamily::Ai => "Ai",
                };

                let mut filter_nodes = Vec::new();
                for (idx, pred) in parsed.predicates.iter().enumerate() {
                    let (expr_str, cost) = match pred {
                        Predicate::CloudType(t) => (format!("cloud.type == '{}'", t), 0.05),
                        Predicate::ApiName(a) => (format!("api.name == '{}'", a), 0.04),
                        Predicate::Region(r) => (format!("region == '{}'", r), 0.03),
                        Predicate::AccountId(acc) => (format!("account_id == '{}'", acc), 0.03),
                        Predicate::JsonRule { path, op, target_value } => {
                            let path_str = path.join(".");
                            let val_str = target_value.as_deref().unwrap_or("none");
                            (format!("json.rule {} {:?} {}", path_str, op, val_str), 0.12)
                        }
                        Predicate::RawExpression(raw) => (format!("raw_expr '{}'", raw), 0.20),
                    };

                    filter_nodes.push(RqlExplainNode {
                        node_type: format!("FilterClause[{}]", idx),
                        target: parsed.target.clone(),
                        expression: expr_str,
                        estimated_cost_ms: cost,
                        children: Vec::new(),
                    });
                }

                let total_pred_cost: f64 = filter_nodes.iter().map(|n| n.estimated_cost_ms).sum();

                let root = RqlExplainNode {
                    node_type: "TableScan".into(),
                    target: format!("{} (from {})", parsed.target, family_name),
                    expression: format!("Scan inventory for target '{}'", parsed.target),
                    estimated_cost_ms: 0.15 + total_pred_cost,
                    children: filter_nodes,
                };

                RqlExplainPlan {
                    raw_query: query_str.to_string(),
                    family: family_name.to_string(),
                    is_valid: true,
                    parse_time_us: parse_time.max(1),
                    ast_root: Some(root),
                    validation_errors: Vec::new(),
                    autocomplete_suggestions: vec![
                        "and json.rule is_public is true".into(),
                        "and region = 'us-east-1'".into(),
                        "and cloud.type = 'aws'".into(),
                    ],
                }
            }
            Err(e) => {
                let parse_time = start.elapsed().as_micros() as u64;
                RqlExplainPlan {
                    raw_query: query_str.to_string(),
                    family: "Unknown".to_string(),
                    is_valid: false,
                    parse_time_us: parse_time.max(1),
                    ast_root: None,
                    validation_errors: vec![e.to_string()],
                    autocomplete_suggestions: vec![
                        "config from cloud.resource where api.name = 'aws_s3_bucket'".into(),
                        "iam from cloud.resource where has_admin_star is true".into(),
                        "network from cloud.resource where allows_public_ssh is true".into(),
                    ],
                }
            }
        }
    }

    /// Validates a policy pack for syntax integrity, required attributes, and framework links.
    pub fn validate_pack(pack: &PolicyPack) -> PolicyPackValidationReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if pack.name.trim().is_empty() {
            errors.push("Policy pack name cannot be empty.".into());
        }
        if pack.version.trim().is_empty() {
            errors.push("Policy pack version cannot be empty.".into());
        }
        if pack.rules.is_empty() {
            warnings.push("Policy pack contains zero rules.".into());
        }

        for rule in &pack.rules {
            if rule.id.trim().is_empty() {
                errors.push("Found policy rule with empty ID.".into());
            }
            if rule.rql_query.trim().is_empty() {
                errors.push(format!("Rule '{}' has an empty RQL query.", rule.id));
            } else if let Err(e) = RqlQuery::parse(&rule.rql_query) {
                errors.push(format!("Rule '{}' syntax error in RQL query: {}", rule.id, e));
            }

            if rule.framework_controls.is_empty() {
                warnings.push(format!("Rule '{}' does not map to any compliance framework controls.", rule.id));
            }

            if rule.pass_fixtures.is_empty() {
                warnings.push(format!("Rule '{}' has no positive (pass) test fixtures.", rule.id));
            }
            if rule.fail_fixtures.is_empty() {
                warnings.push(format!("Rule '{}' has no negative (fail) test fixtures.", rule.id));
            }
        }

        PolicyPackValidationReport {
            pack_name: pack.name.clone(),
            is_valid: errors.is_empty(),
            rule_count: pack.rules.len(),
            errors,
            warnings,
        }
    }

    /// Runs all unit tests embedded in the policy pack against positive and negative fixtures.
    pub fn run_unit_tests(pack: &PolicyPack) -> PolicyPackTestReport {
        let start = std::time::Instant::now();
        let mut results = Vec::new();
        let mut passed_rules = 0;
        let mut failed_rules = 0;

        for rule in &pack.rules {
            let mut pass_passed = 0;
            let mut fail_passed = 0;
            let mut failure_details = Vec::new();

            match RqlQuery::parse(&rule.rql_query) {
                Ok(query) => {
                    // Test PASS fixtures (expected NOT to match rule violation query)
                    for (idx, fixture) in rule.pass_fixtures.iter().enumerate() {
                        let res = convert_json_to_resource(fixture);
                        let matched = query.evaluate(&res);
                        if !matched {
                            pass_passed += 1;
                        } else {
                            failure_details.push(format!(
                                "False positive on pass_fixture[{}]: Compliant resource matched violation query.",
                                idx
                            ));
                        }
                    }

                    // Test FAIL fixtures (expected TO match rule violation query)
                    for (idx, fixture) in rule.fail_fixtures.iter().enumerate() {
                        let res = convert_json_to_resource(fixture);
                        let matched = query.evaluate(&res);
                        if matched {
                            fail_passed += 1;
                        } else {
                            failure_details.push(format!(
                                "False negative on fail_fixture[{}]: Non-compliant resource did NOT match violation query.",
                                idx
                            ));
                        }
                    }
                }
                Err(e) => {
                    failure_details.push(format!("RQL parse error: {}", e));
                }
            }

            let rule_success = failure_details.is_empty()
                && (pass_passed == rule.pass_fixtures.len())
                && (fail_passed == rule.fail_fixtures.len());

            if rule_success {
                passed_rules += 1;
            } else {
                failed_rules += 1;
            }

            results.push(RuleTestOutcome {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                pass_fixtures_passed: pass_passed,
                pass_fixtures_total: rule.pass_fixtures.len(),
                fail_fixtures_passed: fail_passed,
                fail_fixtures_total: rule.fail_fixtures.len(),
                is_success: rule_success,
                failure_details,
            });
        }

        let duration = start.elapsed().as_secs_f64() * 1000.0;

        PolicyPackTestReport {
            pack_name: pack.name.clone(),
            pack_version: pack.version.clone(),
            total_rules: pack.rules.len(),
            passed_rules,
            failed_rules,
            results,
            execution_duration_ms: duration,
        }
    }
}

/// Helper converting arbitrary JSON fixture into a CloudResource for RQL evaluation.
pub fn convert_json_to_resource(val: &serde_json::Value) -> CloudResource {
    let id = val.get("id").and_then(|v| v.as_str()).unwrap_or("res-default").to_string();
    let name = val.get("name").and_then(|v| v.as_str()).unwrap_or("res-name").to_string();
    let arn = val.get("arn").and_then(|v| v.as_str()).unwrap_or(&id).to_string();
    let cloud_str = val.get("cloud_type").and_then(|v| v.as_str()).unwrap_or("aws").to_lowercase();
    let provider = match cloud_str.as_str() {
        "azure" => CloudProvider::Azure,
        "gcp" => CloudProvider::Gcp,
        "k8s" | "kubernetes" => CloudProvider::Kubernetes,
        "oci" => CloudProvider::Oci,
        _ => CloudProvider::Aws,
    };
    let account_id = val.get("account_id").and_then(|v| v.as_str()).unwrap_or("123456789012").to_string();
    let region = val.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1").to_string();
    let api_name = val.get("api").and_then(|a| a.get("name")).and_then(|n| n.as_str()).unwrap_or("cloud.resource");
    let service = val.get("service").and_then(|v| v.as_str()).unwrap_or(api_name).to_string();
    let resource_type = val.get("resource_type").and_then(|v| v.as_str()).unwrap_or(api_name).to_string();

    let mut tags = HashMap::new();
    if let Some(t_obj) = val.get("tags").and_then(|v| v.as_object()) {
        for (k, v) in t_obj {
            if let Some(str_v) = v.as_str() {
                tags.insert(k.clone(), str_v.to_string());
            }
        }
    }

    CloudResource {
        id,
        arn,
        name,
        provider,
        account_id,
        region,
        service,
        resource_type,
        state: val.clone(),
        tags,
    }
}

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("RQL error: {0}")]
    Rql(String),
    #[error("Policy pack error: {0}")]
    Pack(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Commands accepted by PolicySecureEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCommand {
    ExplainQuery(String),
    ValidatePack(String),
    RunUnitTests(String),
    LoadPack(String),
    Clear,
}

/// Snapshot of PolicySecure state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyStateSnapshot {
    pub pack_name: Option<String>,
    pub rules_count: usize,
    pub last_test_report: Option<PolicyPackTestReport>,
    pub last_validation_report: Option<PolicyPackValidationReport>,
}

impl CloudSecureAppEngine for PolicySecureEngine {
    type Command = PolicyCommand;
    type StateSnapshot = PolicyStateSnapshot;
    type Error = PolicyError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 12,
            id: "policysecure",
            name: "PolicySecure",
            pillar: "GOVERNANCE",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Unified RQL and Policy-as-Code Studio with AST explain profiler and test fixture runner.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            PolicyCommand::ExplainQuery(q) => {
                let plan = Self::explain_query(&q);
                let is_valid = plan.is_valid;
                self.last_explain_plan = Some(plan);
                Ok(CommandReceipt {
                    command_name: "ExplainQuery".into(),
                    records_affected: if is_valid { 1 } else { 0 },
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(q.as_bytes())),
                })
            }
            PolicyCommand::ValidatePack(json_str) => {
                let pack: PolicyPack = serde_json::from_str(&json_str)?;
                let report = Self::validate_pack(&pack);
                let rule_count = report.rule_count;
                self.active_pack = Some(pack);
                Ok(CommandReceipt {
                    command_name: "ValidatePack".into(),
                    records_affected: rule_count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            PolicyCommand::RunUnitTests(json_str) => {
                let pack: PolicyPack = serde_json::from_str(&json_str)?;
                let report = Self::run_unit_tests(&pack);
                let passed = report.passed_rules;
                self.test_history.push(report);
                self.active_pack = Some(pack);
                Ok(CommandReceipt {
                    command_name: "RunUnitTests".into(),
                    records_affected: passed,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            PolicyCommand::LoadPack(json_str) => {
                let pack: PolicyPack = serde_json::from_str(&json_str)?;
                let count = pack.rules.len();
                self.active_pack = Some(pack);
                Ok(CommandReceipt {
                    command_name: "LoadPack".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            PolicyCommand::Clear => {
                self.active_pack = None;
                self.test_history.clear();
                self.last_explain_plan = None;
                Ok(CommandReceipt {
                    command_name: "Clear".into(),
                    records_affected: 0,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "empty".into(),
                })
            }
        }
    }

    fn snapshot(&self) -> Self::StateSnapshot {
        PolicyStateSnapshot {
            pack_name: self.active_pack.as_ref().map(|p| p.name.clone()),
            rules_count: self.active_pack.as_ref().map(|p| p.rules.len()).unwrap_or(0),
            last_test_report: self.test_history.last().cloned(),
            last_validation_report: None,
        }
    }

    fn export_sarif(&self) -> SarifReport {
        let mut rules = Vec::new();
        let results = Vec::new();

        if let Some(pack) = &self.active_pack {
            for r in &pack.rules {
                rules.push(SarifRule {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    short_description: SarifMessage {
                        text: r.description.clone(),
                    },
                });
            }
        }

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "PolicySecure".into(),
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
