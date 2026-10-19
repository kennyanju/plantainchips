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
pub enum WaasError {
    #[error("Failed to parse JSON payload: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("OpenAPI specification validation failed: {0}")]
    SpecError(String),
}

/// OpenAPI 3.x parameter specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiParameter {
    pub name: String,
    #[serde(rename = "in")]
    pub in_loc: String,
    pub required: bool,
    pub schema_type: String,
}

/// OpenAPI 3.x endpoint definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiEndpoint {
    pub path: String,
    pub method: String,
    pub summary: Option<String>,
    pub deprecated: bool,
    #[serde(default)]
    pub parameters: Vec<OpenApiParameter>,
    #[serde(default)]
    pub request_body_allowed_fields: Vec<String>,
    #[serde(default)]
    pub requires_auth: bool,
    #[serde(default)]
    pub rate_limit_rpm: Option<u32>,
}

/// OpenAPI specification metadata and endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub title: String,
    pub version: String,
    #[serde(default)]
    pub endpoints: Vec<OpenApiEndpoint>,
}

/// Authenticated identity for an incoming API request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiUserIdentity {
    pub user_id: String,
    pub role: String,
    pub org_id: String,
}

/// Live HTTP/REST API traffic record captured at the gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApiTrafficRecord {
    pub id: String,
    pub timestamp: String,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub query_params: HashMap<String, String>,
    pub request_body: Option<serde_json::Value>,
    pub status_code: u16,
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    pub response_body: Option<serde_json::Value>,
    pub user_identity: Option<ApiUserIdentity>,
}

impl ApiTrafficRecord {
    pub fn state_hash(&self) -> String {
        let raw = format!("{}:{}:{}:{}", self.id, self.method, self.uri, self.client_ip);
        format!("{:x}", Sha256::digest(raw.as_bytes()))
    }
}

/// WAAS diagnostic finding reflecting an OWASP API Top 10 or drift condition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WaasViolation {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub traffic_id: String,
    pub endpoint: String,
    pub method: String,
    pub evidence_detail: String,
    pub suggested_waf_rule: Option<String>,
}

/// Cloudflare and AWS WAF rule sets synthesized from security policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedWafRules {
    pub cloudflare_expression: String,
    pub aws_waf_rule_json: String,
}

/// Core WAAS and OWASP API inspection engine.
pub struct WaasEngine {
    pub spec: Option<OpenApiSpec>,
    pub traffic_records: Vec<ApiTrafficRecord>,
    pub findings: Vec<Finding>,
}

impl Default for WaasEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub fn matches_path_template(spec_path: &str, traffic_uri: &str) -> bool {
    let spec_clean = spec_path.trim_matches('/');
    let traffic_clean = traffic_uri.split('?').next().unwrap_or(traffic_uri).trim_matches('/');
    let s_segs: Vec<&str> = spec_clean.split('/').filter(|s| !s.is_empty()).collect();
    let t_segs: Vec<&str> = traffic_clean.split('/').filter(|s| !s.is_empty()).collect();

    if s_segs.len() != t_segs.len() {
        return false;
    }

    for (s, t) in s_segs.iter().zip(t_segs.iter()) {
        if s.starts_with('{') && s.ends_with('}') {
            continue;
        }
        if !s.eq_ignore_ascii_case(t) {
            return false;
        }
    }
    true
}

impl WaasEngine {
    pub fn new() -> Self {
        Self {
            spec: None,
            traffic_records: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Evaluates traffic against OWASP API Security Top 10 policies.
    pub fn evaluate_traffic(
        record: &ApiTrafficRecord,
        spec: Option<&OpenApiSpec>,
    ) -> Vec<WaasViolation> {
        let mut violations = Vec::new();

        // 1. API2:2023 - Broken Authentication
        let auth_hdr = record
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.as_str());

        let requires_auth = if let Some(sp) = spec {
            sp.endpoints.iter().any(|ep| {
                matches_path_template(&ep.path, &record.uri)
                    && ep.method.eq_ignore_ascii_case(&record.method)
                    && ep.requires_auth
            })
        } else {
            record.uri.starts_with("/api/")
        };

        if requires_auth {
            if auth_hdr.is_none()
                || auth_hdr == Some("")
                || auth_hdr == Some("Bearer null")
                || auth_hdr == Some("Bearer undefined")
            {
                violations.push(WaasViolation {
                    rule_id: "API2:2023".into(),
                    category: "Broken Authentication".into(),
                    severity: Severity::Critical,
                    title: "Missing or Unauthenticated Bearer Token".into(),
                    message: format!(
                        "Endpoint '{}' requires authentication but request lacked a valid Authorization header.",
                        record.uri
                    ),
                    traffic_id: record.id.clone(),
                    endpoint: record.uri.clone(),
                    method: record.method.clone(),
                    evidence_detail: "Authorization header is missing or contains null token".into(),
                    suggested_waf_rule: Some(format!(
                        "http.request.uri.path eq \"{}\" and not any(http.request.headers[\"authorization\"][*] matches \"^Bearer [A-Za-z0-9-_]+\\\\.[A-Za-z0-9-_]+\\\\.[A-Za-z0-9-_]+$\")",
                        record.uri
                    )),
                });
            }
        }

        // 2. API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        if let Some(user) = &record.user_identity {
            // Check if URI contains an explicit userId parameter that mismatches the token identity
            if record.uri.contains("/users/") {
                let parts: Vec<&str> = record.uri.split('/').collect();
                if let Some(pos) = parts.iter().position(|&p| p == "users") {
                    if pos + 1 < parts.len() {
                        let target_user_id = parts[pos + 1];
                        if target_user_id != user.user_id && user.role != "admin" {
                            violations.push(WaasViolation {
                                rule_id: "API1:2023".into(),
                                category: "Broken Object Level Authorization (BOLA)".into(),
                                severity: Severity::Critical,
                                title: "Cross-Tenant Object Access Disallowed (BOLA/IDOR)".into(),
                                message: format!(
                                    "User '{}' with role '{}' attempted to access object belonging to user '{}'.",
                                    user.user_id, user.role, target_user_id
                                ),
                                traffic_id: record.id.clone(),
                                endpoint: record.uri.clone(),
                                method: record.method.clone(),
                                evidence_detail: format!(
                                    "Token user_id='{}' differs from path target_user_id='{}'",
                                    user.user_id, target_user_id
                                ),
                                suggested_waf_rule: Some(
                                    "Enforce JWT claim validation at API gateway filter layer".into(),
                                ),
                            });
                        }
                    }
                }
            }
        }

        // 3. API3:2023 - Broken Object Property Level Authorization (Mass Assignment & Excessive Data Exposure)
        if let Some(body) = &record.request_body {
            if let Some(obj) = body.as_object() {
                let dangerous_properties = ["is_admin", "role", "is_verified", "billing_tier", "balance", "permissions"];
                for prop in dangerous_properties {
                    if obj.contains_key(prop) {
                        violations.push(WaasViolation {
                            rule_id: "API3:2023".into(),
                            category: "Broken Object Property Level Authorization (Mass Assignment)".into(),
                            severity: Severity::High,
                            title: format!("Mass Assignment Attempt for Sensitive Property '{}'", prop),
                            message: format!(
                                "Client supplied privileged property '{}' in request payload to endpoint '{}'.",
                                prop, record.uri
                            ),
                            traffic_id: record.id.clone(),
                            endpoint: record.uri.clone(),
                            method: record.method.clone(),
                            evidence_detail: format!("Request body contains sensitive field: \"{}\"", prop),
                            suggested_waf_rule: Some(format!(
                                "http.request.uri.path eq \"{}\" and http.request.body.raw contains \"\\\"{}\\\"\"",
                                record.uri, prop
                            )),
                        });
                    }
                }
            }
        }

        // Sensitive Data Exposure in response body
        if let Some(resp_body) = &record.response_body {
            let resp_str = resp_body.to_string();
            let sensitive_tokens = ["password_hash", "private_key", "ssn", "secret_key"];
            for token in sensitive_tokens {
                if resp_str.contains(token) {
                    violations.push(WaasViolation {
                        rule_id: "API3:2023".into(),
                        category: "Broken Object Property Level Authorization (Excessive Data Exposure)".into(),
                        severity: Severity::Critical,
                        title: format!("API Exposes Sensitive Property '{}' in Response", token),
                        message: format!(
                            "Endpoint '{}' returned sensitive credential or personal identifier in response body.",
                            record.uri
                        ),
                        traffic_id: record.id.clone(),
                        endpoint: record.uri.clone(),
                        method: record.method.clone(),
                        evidence_detail: format!("Response body contains property '{}'", token),
                        suggested_waf_rule: None,
                    });
                }
            }
        }

        // 4. API4:2023 - Unrestricted Resource Consumption
        if let Some(limit_str) = record.query_params.get("limit") {
            if let Ok(limit_val) = limit_str.parse::<u64>() {
                if limit_val > 1000 {
                    violations.push(WaasViolation {
                        rule_id: "API4:2023".into(),
                        category: "Unrestricted Resource Consumption".into(),
                        severity: Severity::Medium,
                        title: "Excessive Collection Query Pagination Limit".into(),
                        message: format!(
                            "Request specified pagination limit of {} items, which exceeds the max allowed limit of 1000.",
                            limit_val
                        ),
                        traffic_id: record.id.clone(),
                        endpoint: record.uri.clone(),
                        method: record.method.clone(),
                        evidence_detail: format!("Query parameter limit={}", limit_val),
                        suggested_waf_rule: Some("http.request.uri.query contains \"limit=\" and int(http.request.uri.args[\"limit\"][0]) > 1000".into()),
                    });
                }
            }
        }

        // 5. API5:2023 - Broken Function Level Authorization (BFLA)
        if record.uri.starts_with("/admin/") || record.uri.starts_with("/api/internal/") {
            let user_role = record.user_identity.as_ref().map(|u| u.role.as_str()).unwrap_or("anonymous");
            if user_role != "admin" && user_role != "superadmin" {
                violations.push(WaasViolation {
                    rule_id: "API5:2023".into(),
                    category: "Broken Function Level Authorization (BFLA)".into(),
                    severity: Severity::Critical,
                    title: "Unauthorized Role Accessed Administrative Function".into(),
                    message: format!(
                        "User with role '{}' attempted to access privileged function '{}'.",
                        user_role, record.uri
                    ),
                    traffic_id: record.id.clone(),
                    endpoint: record.uri.clone(),
                    method: record.method.clone(),
                    evidence_detail: format!("Role '{}' denied for URI path '{}'", user_role, record.uri),
                    suggested_waf_rule: Some(format!(
                        "http.request.uri.path contains \"{}\" and not ip.src in {{10.0.0.0/8, 172.16.0.0/12}}",
                        record.uri
                    )),
                });
            }
        }

        // 6. API8:2023 - Security Misconfiguration (CORS wildcard with credentials & verbose errors)
        if let Some(cors_val) = record.response_headers.get("access-control-allow-origin") {
            if cors_val == "*" && record.response_headers.contains_key("access-control-allow-credentials") {
                violations.push(WaasViolation {
                    rule_id: "API8:2023".into(),
                    category: "Security Misconfiguration".into(),
                    severity: Severity::High,
                    title: "Insecure CORS Policy Combining Wildcard Origin and Credentials".into(),
                    message: "Access-Control-Allow-Origin: * combined with credentials allows unauthorized cross-origin reading.".into(),
                    traffic_id: record.id.clone(),
                    endpoint: record.uri.clone(),
                    method: record.method.clone(),
                    evidence_detail: "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true".into(),
                    suggested_waf_rule: None,
                });
            }
        }

        // 7. API9:2023 - Improper Inventory Management (Shadow APIs & Zombie APIs)
        if let Some(sp) = spec {
            let matching_endpoint = sp.endpoints.iter().find(|ep| {
                matches_path_template(&ep.path, &record.uri) && ep.method.eq_ignore_ascii_case(&record.method)
            });

            match matching_endpoint {
                None => {
                    // Shadow API: Endpoint observed in live traffic with no OpenAPI registration
                    violations.push(WaasViolation {
                        rule_id: "API9:2023".into(),
                        category: "Improper Inventory Management (Shadow API)".into(),
                        severity: Severity::High,
                        title: "Shadow API Endpoint Undocumented in OpenAPI Specification".into(),
                        message: format!(
                            "Observed HTTP {} '{}' in live production traffic, but endpoint is missing from OpenAPI 3.x catalog.",
                            record.method, record.uri
                        ),
                        traffic_id: record.id.clone(),
                        endpoint: record.uri.clone(),
                        method: record.method.clone(),
                        evidence_detail: "Endpoint not documented in active OpenAPI spec".into(),
                        suggested_waf_rule: Some(format!(
                            "Block or route undocumented endpoint '{}' to quarantine inspection",
                            record.uri
                        )),
                    });
                }
                Some(ep) if ep.deprecated => {
                    // Zombie API: Endpoint is marked deprecated in OpenAPI spec but still active
                    violations.push(WaasViolation {
                        rule_id: "API9:2023".into(),
                        category: "Improper Inventory Management (Zombie API)".into(),
                        severity: Severity::Medium,
                        title: "Deprecated Zombie API Endpoint Receiving Live Traffic".into(),
                        message: format!(
                            "Endpoint HTTP {} '{}' is deprecated in specification but continues to receive incoming requests.",
                            ep.method, ep.path
                        ),
                        traffic_id: record.id.clone(),
                        endpoint: record.uri.clone(),
                        method: record.method.clone(),
                        evidence_detail: "Endpoint marked deprecated=true in specification".into(),
                        suggested_waf_rule: None,
                    });
                }
                _ => {}
            }
        }

        violations
    }

    /// Synthesizes WAF rules from all collected violations.
    pub fn synthesize_waf_rules(violations: &[WaasViolation]) -> SynthesizedWafRules {
        let mut cf_expressions = Vec::new();
        let mut aws_statements = Vec::new();

        for (idx, v) in violations.iter().enumerate() {
            if let Some(rule) = &v.suggested_waf_rule {
                if rule.starts_with("http.") {
                    cf_expressions.push(format!("({})", rule));
                }
            }

            // AWS WAF ByteMatch statement for mass assignment or admin endpoints
            if v.rule_id == "API5:2023" {
                aws_statements.push(serde_json::json!({
                    "Name": format!("BlockAdminUri-{}", idx),
                    "Priority": idx + 1,
                    "Action": { "Block": {} },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": true,
                        "CloudWatchMetricsEnabled": true,
                        "MetricName": format!("waas-admin-block-{}", idx)
                    },
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": v.endpoint,
                            "FieldToMatch": { "UriPath": {} },
                            "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                            "PositionalConstraint": "STARTS_WITH"
                        }
                    }
                }));
            }
        }

        let combined_cf = if cf_expressions.is_empty() {
            "# No custom WAF rules required for current clean traffic baseline".into()
        } else {
            cf_expressions.join(" or\n")
        };

        let combined_aws = serde_json::to_string_pretty(&serde_json::json!({
            "Name": "CloudSecure-WAF-RuleGroup",
            "Scope": "REGIONAL",
            "Capacity": 250,
            "Rules": aws_statements
        }))
        .unwrap_or_else(|_| "{}".into());

        SynthesizedWafRules {
            cloudflare_expression: combined_cf,
            aws_waf_rule_json: combined_aws,
        }
    }

    pub fn recompute(&mut self) {
        self.findings.clear();

        for record in &self.traffic_records {
            let violations = Self::evaluate_traffic(record, self.spec.as_ref());
            for v in violations {
                let evidence = Evidence {
                    rule_id: v.rule_id.clone(),
                    target_path: format!("{} {}", v.method, v.endpoint),
                    expected_value: "Compliant with OWASP API Security and OpenAPI contract".into(),
                    observed_value: v.evidence_detail.clone(),
                    message: v.message.clone(),
                    resource_state_hash: record.state_hash(),
                };

                let remediation_code = v.suggested_waf_rule.clone().unwrap_or_else(|| {
                    "# Patch backend application controller to enforce authorization check".into()
                });

                self.findings.push(Finding {
                    id: format!("{}-{}-{}", v.rule_id, record.id, v.endpoint.replace('/', "-")),
                    rule_id: v.rule_id.clone(),
                    title: v.title.clone(),
                    severity: v.severity,
                    status: FindingStatus::Fail,
                    provider: CloudProvider::Aws,
                    account_id: "api-gateway".into(),
                    region: "global".into(),
                    resource_id: format!("{} {}", v.method, v.endpoint),
                    resource_arn: format!("arn:aws:apigateway:us-east-1::/restapis/gateway/resources/{}", record.id),
                    resource_type: "AWS::ApiGateway::Method".into(),
                    framework_mappings: vec!["OWASP API Security Top 10:2023".into(), v.category.clone()],
                    evidence,
                    remediation: Some(RemediationPatch {
                        format: RemediationFormat::CloudflareWaf,
                        code: remediation_code.clone(),
                        sha256_hash: format!("{:x}", Sha256::digest(remediation_code.as_bytes())),
                    }),
                    timestamp: Utc::now(),
                });
            }
        }
    }
}

/// Commands accepted by the WaasEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WaasCommand {
    LoadSpec(String),
    LoadTraffic(String),
    Clear,
}

/// Snapshot of the WaasEngine state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaasStateSnapshot {
    pub spec_loaded: bool,
    pub spec_title: Option<String>,
    pub traffic_records_count: usize,
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

impl CloudSecureAppEngine for WaasEngine {
    type Command = WaasCommand;
    type StateSnapshot = WaasStateSnapshot;
    type Error = WaasError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 6,
            id: "waassecure",
            name: "WaasSecure",
            pillar: "WAAS",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Web Application and API Security (WAAS) inspecting OWASP API Top 10 vulnerabilities, OpenAPI contract drift, and synthesizing WAF rules.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            WaasCommand::LoadSpec(json_str) => {
                let parsed: OpenApiSpec = serde_json::from_str(&json_str)?;
                let count = parsed.endpoints.len();
                self.spec = Some(parsed);
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadSpec".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            WaasCommand::LoadTraffic(json_str) => {
                let records: Vec<ApiTrafficRecord> = serde_json::from_str(&json_str)?;
                let count = records.len();
                self.traffic_records = records;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadTraffic".into(),
                    records_affected: count,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:x}", Sha256::digest(json_str.as_bytes())),
                })
            }
            WaasCommand::Clear => {
                let count = self.traffic_records.len();
                self.spec = None;
                self.traffic_records.clear();
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
        WaasStateSnapshot {
            spec_loaded: self.spec.is_some(),
            spec_title: self.spec.as_ref().map(|s| s.title.clone()),
            traffic_records_count: self.traffic_records.len(),
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
                help_uri: format!("https://owasp.org/API-Security/editions/2023/en/0xa1-{}", f.rule_id.to_lowercase().replace(':', "-")),
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
                        name: "WaasSecure".into(),
                        version: "0.1.0".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}
