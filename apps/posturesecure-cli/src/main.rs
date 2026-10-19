use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use posturesecure::{ComplianceMapper, PostureCommand, PostureEngine};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "posturesecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "PostureSecure: 100% Pure Rust Cloud Security Posture Management CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan cloud resource inventory against CIS compliance policies and RQL rules
    Scan {
        /// Path to JSON resource snapshot inventory file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,

        /// Optional inline RQL predicate filter
        #[arg(long)]
        rql: Option<String>,
    },

    /// Evaluate an ad-hoc RQL statement against a cloud resource snapshot
    Query {
        /// RQL query string (e.g. "config from cloud.resource where ...")
        query: String,

        /// Path to JSON resource snapshot inventory file
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Generate deterministic Terraform HCL or CLI remediation patch for a policy rule
    Remediate {
        /// Policy rule ID (e.g. CIS-AWS-3.0-2.1.1)
        #[arg(long)]
        rule: String,

        /// Target resource name
        #[arg(long)]
        resource_name: String,
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
        Some(Commands::Scan { input, format, rql }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = PostureEngine::new();
            engine.execute(PostureCommand::IngestJson(json_content))?;

            let findings = if let Some(query_str) = rql {
                let mapper = ComplianceMapper::new();
                let matched_resources = mapper.evaluate_rql(&engine.inventory, &query_str)?;
                let mut filtered = Vec::new();
                for r in matched_resources {
                    for f in &engine.findings {
                        if f.resource_id == r.id {
                            filtered.push(f.clone());
                        }
                    }
                }
                filtered
            } else {
                engine.findings.clone()
            };

            output_findings(&findings, format, &engine)?;
            if findings.iter().any(|f| f.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::Query { query, input }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = PostureEngine::new();
            engine.execute(PostureCommand::IngestJson(json_content))?;

            let mapper = ComplianceMapper::new();
            let matched = mapper.evaluate_rql(&engine.inventory, &query)?;
            println!("RQL Query Matched {} cloud resources:", matched.len());
            for r in matched {
                println!("- [{}] {} ({}) - {}", r.provider, r.name, r.resource_type, r.arn);
            }
        }
        Some(Commands::Remediate { rule, resource_name }) => {
            let rules = cloudsecure_policy::standard_cspm_rules();
            if let Some(r) = rules.iter().find(|x| x.id.eq_ignore_ascii_case(&rule)) {
                let patch = r.remediation_hcl.replace("{{RESOURCE_ID}}", &resource_name);
                println!("# Remediation Patch for Rule {}\n{}", r.id, patch);
            } else {
                eprintln!("Unknown policy rule: {}. Run scan to list valid rule IDs.", rule);
                std::process::exit(1);
            }
        }
        None => {
            eprintln!("No command provided. Run with --help or pass --mcp to start agent server.");
        }
    }

    Ok(())
}

fn output_findings(
    findings: &[Finding],
    format: OutputFormat,
    engine: &PostureEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<20} {:<30} {:<40}", "SEVERITY", "RULE ID", "RESOURCE", "TITLE");
            println!("{}", "-".repeat(105));
            for f in findings {
                println!(
                    "{:<10} {:<20} {:<30} {:<40}",
                    format!("{} {:?}", f.severity.glyph(), f.severity),
                    f.rule_id,
                    f.resource_id,
                    f.title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total Findings: {}", findings.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(findings)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif => {
            let sarif = engine.export_sarif();
            let serialized = serde_json::to_string_pretty(&sarif)?;
            println!("{}", serialized);
        }
        OutputFormat::Csv => {
            println!("Severity,RuleID,ResourceID,ResourceArn,Title,Message");
            for f in findings {
                println!(
                    "{:?},{},{},{},\"{}\",\"{}\"",
                    f.severity, f.rule_id, f.resource_id, f.resource_arn, f.title, f.evidence.message
                );
            }
        }
    }
    Ok(())
}

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP).
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
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "posturesecure-mcp",
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
                            "name": "posture_run_rql",
                            "description": "Execute an RQL query (e.g. 'config from cloud.resource where ...') against a cloud inventory",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "query": { "type": "string" },
                                    "inventory_json": { "type": "string" }
                                },
                                "required": ["query", "inventory_json"]
                            }
                        },
                        {
                            "name": "posture_evaluate_compliance",
                            "description": "Evaluate multi-cloud inventory against standard CIS benchmarks",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "inventory_json": { "type": "string" }
                                },
                                "required": ["inventory_json"]
                            }
                        },
                        {
                            "name": "posture_generate_remediation",
                            "description": "Generate Terraform HCL patch for a specific finding or rule",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "rule_id": { "type": "string" },
                                    "resource_name": { "type": "string" }
                                },
                                "required": ["rule_id", "resource_name"]
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
                    "posture_evaluate_compliance" => {
                        let inv_str = args.get("inventory_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = PostureEngine::new();
                        match engine.execute(PostureCommand::IngestJson(inv_str.into())) {
                            Ok(_) => serde_json::json!({
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "posture_run_rql" => {
                        let query = args.get("query").and_then(|s| s.as_str()).unwrap_or("");
                        let inv_str = args.get("inventory_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = PostureEngine::new();
                        let _ = engine.execute(PostureCommand::IngestJson(inv_str.into()));
                        let mapper = ComplianceMapper::new();
                        match mapper.evaluate_rql(&engine.inventory, query) {
                            Ok(matched) => serde_json::json!({
                                "matched_count": matched.len(),
                                "resources": matched
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "posture_generate_remediation" => {
                        let rule_id = args.get("rule_id").and_then(|s| s.as_str()).unwrap_or("");
                        let res_name = args.get("resource_name").and_then(|s| s.as_str()).unwrap_or("target");
                        let rules = cloudsecure_policy::standard_cspm_rules();
                        if let Some(r) = rules.iter().find(|x| x.id.eq_ignore_ascii_case(rule_id)) {
                            let patch = r.remediation_hcl.replace("{{RESOURCE_ID}}", res_name);
                            serde_json::json!({ "rule_id": r.id, "terraform_patch": patch })
                        } else {
                            serde_json::json!({ "error": format!("Rule {} not found", rule_id) })
                        }
                    }
                    _ => serde_json::json!({ "error": format!("Unknown tool: {}", name) }),
                };

                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": serde_json::to_string_pretty(&tool_result).unwrap_or_default()
                            }
                        ]
                    }
                })
            }
            _ => serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
            }),
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}
