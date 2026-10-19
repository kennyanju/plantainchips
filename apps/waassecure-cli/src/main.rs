use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use waassecure::{ApiTrafficRecord, OpenApiSpec, WaasCommand, WaasEngine};

#[derive(Parser, Debug)]
#[command(name = "waassecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "WaasSecure: Web Application & API Security CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect API traffic logs against OWASP API Security Top 10 rules
    Scan {
        /// Path to API traffic logs JSON
        #[arg(short, long)]
        traffic: PathBuf,

        /// Path to OpenAPI 3.x specification JSON (optional)
        #[arg(short, long)]
        spec: Option<PathBuf>,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Detect OpenAPI specification drift (Shadow APIs and deprecated Zombie APIs)
    Drift {
        /// Path to API traffic logs JSON
        #[arg(short, long)]
        traffic: PathBuf,

        /// Path to OpenAPI 3.x specification JSON
        #[arg(short, long)]
        spec: PathBuf,
    },

    /// Synthesize Cloudflare WAF and AWS WAF rule sets from traffic violations
    WafRules {
        /// Path to API traffic logs JSON
        #[arg(short, long)]
        traffic: PathBuf,

        /// Target WAF platform (cloudflare, aws, all)
        #[arg(long, default_value = "all")]
        target: String,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
    Sarif,
    Csv,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.mcp {
        run_mcp_server().await?;
        return Ok(());
    }

    match cli.command {
        Some(Commands::Scan {
            traffic,
            spec,
            format,
        }) => {
            let mut engine = WaasEngine::new();
            if let Some(spec_path) = spec {
                let spec_content = fs::read_to_string(&spec_path)?;
                engine.execute(WaasCommand::LoadSpec(spec_content))?;
            }
            let traffic_content = fs::read_to_string(&traffic)?;
            engine.execute(WaasCommand::LoadTraffic(traffic_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::Drift { traffic, spec }) => {
            let mut engine = WaasEngine::new();
            let spec_content = fs::read_to_string(&spec)?;
            engine.execute(WaasCommand::LoadSpec(spec_content))?;
            let traffic_content = fs::read_to_string(&traffic)?;
            engine.execute(WaasCommand::LoadTraffic(traffic_content))?;

            let drift_findings: Vec<&Finding> = engine
                .findings
                .iter()
                .filter(|f| f.rule_id == "API9:2023")
                .collect();

            println!(
                "{:<10} {:<16} {:<32} {}",
                "SEVERITY", "RULE ID", "ENDPOINT", "TITLE"
            );
            println!("{}", "-".repeat(95));
            for f in &drift_findings {
                println!(
                    "{:<10} {:<16} {:<32} {}",
                    format!("{:?}", f.severity),
                    f.rule_id,
                    f.resource_id,
                    f.title
                );
            }
            println!("{}", "-".repeat(95));
            println!("Total OpenAPI Drift Findings: {}", drift_findings.len());
        }
        Some(Commands::WafRules { traffic, target }) => {
            let traffic_content = fs::read_to_string(&traffic)?;
            let records: Vec<ApiTrafficRecord> = serde_json::from_str(&traffic_content)?;

            let mut all_violations = Vec::new();
            for r in &records {
                all_violations.extend(WaasEngine::evaluate_traffic(r, None));
            }
            let rules = WaasEngine::synthesize_waf_rules(&all_violations);

            if target == "cloudflare" || target == "all" {
                println!("=== Cloudflare WAF Expression Ruleset ===");
                println!("{}\n", rules.cloudflare_expression);
            }
            if target == "aws" || target == "all" {
                println!("=== AWS WAFv2 Rule Group (JSON) ===");
                println!("{}", rules.aws_waf_rule_json);
            }
        }
        None => {
            eprintln!("Error: No command specified. Use --help for usage details.");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn output_findings(
    findings: &[Finding],
    format: OutputFormat,
    engine: &WaasEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!(
                "{:<10} {:<12} {:<34} {}",
                "SEVERITY", "RULE ID", "ENDPOINT", "TITLE"
            );
            println!("{}", "-".repeat(105));
            for f in findings {
                let glyph = if f.severity == cloudsecure_types::Severity::Critical {
                    "[!]"
                } else {
                    "[/!\\]"
                };
                let display_title = if f.title.len() > 45 {
                    format!("{}...", &f.title[..42])
                } else {
                    f.title.clone()
                };
                println!(
                    "{:<10} {:<12} {:<34} {}",
                    format!("{} {:?}", glyph, f.severity),
                    f.rule_id,
                    f.resource_id,
                    display_title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total OWASP API Security Findings: {}", findings.len());
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(findings)?);
        }
        OutputFormat::Sarif => {
            let sarif = engine.export_sarif();
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Csv => {
            println!("Severity,RuleId,Endpoint,Title,Message");
            for f in findings {
                println!(
                    "{:?},{},{},\"{}\",\"{}\"",
                    f.severity, f.rule_id, f.resource_id, f.title, f.evidence.message
                );
            }
        }
    }
    Ok(())
}

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for WaasSecure.
async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let request: serde_json::Value = serde_json::from_str(&line)?;
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "waassecure-mcp",
                        "version": "0.1.0"
                    }
                }
            }),
            "tools/list" => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": [
                        {
                            "name": "waas_inspect_traffic",
                            "description": "Inspect API traffic records against OWASP API Security Top 10 vulnerabilities (BOLA, Broken Auth, Mass Assignment, BFLA, Misconfiguration)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "traffic_json": { "type": "string" },
                                    "spec_json": { "type": "string" }
                                },
                                "required": ["traffic_json"]
                            }
                        },
                        {
                            "name": "waas_detect_openapi_drift",
                            "description": "Detect undocumented Shadow APIs and deprecated Zombie APIs by contrasting traffic with OpenAPI specification",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "traffic_json": { "type": "string" },
                                    "spec_json": { "type": "string" }
                                },
                                "required": ["traffic_json", "spec_json"]
                            }
                        },
                        {
                            "name": "waas_synthesize_waf_rules",
                            "description": "Synthesize Cloudflare WAF expressions and AWS WAF rule groups from detected API violations",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "traffic_json": { "type": "string" }
                                },
                                "required": ["traffic_json"]
                            }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let params = request.get("params");
                let name = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
                let args = params.and_then(|p| p.get("arguments")).cloned().unwrap_or(serde_json::json!({}));

                let tool_result = match name {
                    "waas_inspect_traffic" => {
                        let traffic_str = args.get("traffic_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = WaasEngine::new();
                        if let Some(spec_str) = args.get("spec_json").and_then(|s| s.as_str()) {
                            let _ = engine.execute(WaasCommand::LoadSpec(spec_str.into()));
                        }
                        match engine.execute(WaasCommand::LoadTraffic(traffic_str.into())) {
                            Ok(_) => serde_json::json!({
                                "traffic_records_scanned": engine.traffic_records.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "waas_detect_openapi_drift" => {
                        let traffic_str = args.get("traffic_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let spec_str = args.get("spec_json").and_then(|s| s.as_str()).unwrap_or("{}");
                        let mut engine = WaasEngine::new();
                        let _ = engine.execute(WaasCommand::LoadSpec(spec_str.into()));
                        let _ = engine.execute(WaasCommand::LoadTraffic(traffic_str.into()));

                        let drift: Vec<&Finding> = engine.findings.iter().filter(|f| f.rule_id == "API9:2023").collect();
                        serde_json::json!({
                            "drift_count": drift.len(),
                            "drift_findings": drift
                        })
                    }
                    "waas_synthesize_waf_rules" => {
                        let traffic_str = args.get("traffic_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        match serde_json::from_str::<Vec<ApiTrafficRecord>>(traffic_str) {
                            Ok(records) => {
                                let mut all_violations = Vec::new();
                                for r in &records {
                                    all_violations.extend(WaasEngine::evaluate_traffic(r, None));
                                }
                                let rules = WaasEngine::synthesize_waf_rules(&all_violations);
                                serde_json::json!({
                                    "cloudflare_expression": rules.cloudflare_expression,
                                    "aws_waf_rule_json": rules.aws_waf_rule_json
                                })
                            }
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    _ => serde_json::json!({ "error": format!("Unknown tool: {}", name) }),
                };

                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": serde_json::to_string_pretty(&tool_result)?
                        }]
                    }
                })
            }
            _ => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}
