use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use identitysecure::{EscalationVector, IdentityCommand, IdentityEngine, RightSizingReport};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "identitysecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "IdentitySecure: CIEM Net-Effective Permissions & Privilege Escalation CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze cloud IAM principals for privilege escalation paths and excessive entitlement gaps
    Analyze {
        /// Path to IAM bundle snapshot JSON file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Detect critical cloud IAM privilege escalation vectors (e.g. PassRole, CreatePolicyVersion)
    Escalation {
        /// Path to IAM bundle snapshot JSON file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Synthesize least-privilege IAM policy by trimming unused actions based on 90-day CloudTrail usage
    RightSize {
        /// Path to IAM bundle snapshot JSON file
        #[arg(short, long)]
        input: PathBuf,

        /// Target principal name or ID
        #[arg(short, long)]
        principal: Option<String>,
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
        Some(Commands::Analyze { input, format }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = IdentityEngine::new();
            engine.execute(IdentityCommand::LoadPrincipals(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine.findings.iter().any(|f| f.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::Escalation { input, format }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = IdentityEngine::new();
            engine.execute(IdentityCommand::LoadPrincipals(json_content))?;

            output_escalations(&engine.escalations, format)?;
        }
        Some(Commands::RightSize { input, principal }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = IdentityEngine::new();
            engine.execute(IdentityCommand::LoadPrincipals(json_content))?;

            let targets: Vec<&RightSizingReport> = if let Some(ref p_name) = principal {
                engine
                    .right_sizing
                    .iter()
                    .filter(|r| r.principal_arn.to_lowercase().contains(&p_name.to_lowercase()))
                    .collect()
            } else {
                engine.right_sizing.iter().collect()
            };

            for r in targets {
                println!("{}", "-".repeat(90));
                println!("Principal ARN            : {}", r.principal_arn);
                println!("Granted Actions Count    : {}", r.granted_actions_count);
                println!("Observed Used Actions    : {}", r.used_actions_count);
                println!("Unused Actions Stripped  : {}", r.unused_actions_count);
                println!("Entitlement Gap Reduction: {:.1}%", r.entitlement_gap_percentage);
                println!("\nSynthesized Least-Privilege Terraform Patch:\n{}", r.remediation_hcl);
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
    engine: &IdentityEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<16} {:<32} {:<42}", "SEVERITY", "RULE ID", "PRINCIPAL", "TITLE");
            println!("{}", "-".repeat(105));
            for f in findings {
                println!(
                    "{:<10} {:<16} {:<32} {:<42}",
                    format!("{} {:?}", f.severity.glyph(), f.severity),
                    f.rule_id,
                    f.resource_id,
                    f.title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total Entitlement Findings: {}", findings.len());
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
            println!("Severity,RuleId,ResourceId,ResourceArn,Title,Message");
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

fn output_escalations(
    escalations: &[EscalationVector],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<16} {:<36} {:<36}", "SEVERITY", "VECTOR ID", "PRINCIPAL ARN", "VECTOR NAME");
            println!("{}", "-".repeat(100));
            for e in escalations {
                println!(
                    "{:<10} {:<16} {:<36} {:<36}",
                    format!("{} {:?}", e.severity.glyph(), e.severity),
                    e.vector_id,
                    if e.principal_arn.len() > 36 { format!("{}...", &e.principal_arn[..33]) } else { e.principal_arn.clone() },
                    e.name
                );
            }
            println!("{}", "-".repeat(100));
            println!("Total Privilege Escalation Vectors: {}", escalations.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(escalations)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif | OutputFormat::Csv => {
            println!("Severity,VectorId,PrincipalArn,Name,RequiredActions,Description");
            for e in escalations {
                println!(
                    "{:?},{},{},\"{}\",\"{}\",\"{}\"",
                    e.severity, e.vector_id, e.principal_arn, e.name, e.required_actions.join(";"), e.description
                );
            }
        }
    }
    Ok(())
}

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for IdentitySecure.
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
                        "name": "identitysecure-mcp",
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
                            "name": "ciem_compute_effective_permissions",
                            "description": "Compute net-effective permissions across IAM policies, boundaries, and SCPs",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "iam_bundle_json": { "type": "string" }
                                },
                                "required": ["iam_bundle_json"]
                            }
                        },
                        {
                            "name": "ciem_find_escalation_paths",
                            "description": "Identify privilege escalation vectors that allow identity to gain admin privileges",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "iam_bundle_json": { "type": "string" }
                                },
                                "required": ["iam_bundle_json"]
                            }
                        },
                        {
                            "name": "ciem_synthesize_least_privilege",
                            "description": "Synthesize least-privilege IAM policy by stripping unused actions based on observed activity",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "iam_bundle_json": { "type": "string" },
                                    "principal_arn": { "type": "string" }
                                },
                                "required": ["iam_bundle_json"]
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
                    "ciem_compute_effective_permissions" => {
                        let json_str = args.get("iam_bundle_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = IdentityEngine::new();
                        match engine.execute(IdentityCommand::LoadPrincipals(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "principals_count": engine.principals.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "ciem_find_escalation_paths" => {
                        let json_str = args.get("iam_bundle_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = IdentityEngine::new();
                        match engine.execute(IdentityCommand::LoadPrincipals(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "escalations_count": engine.escalations.len(),
                                "escalations": engine.escalations
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "ciem_synthesize_least_privilege" => {
                        let json_str = args.get("iam_bundle_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let p_filter = args.get("principal_arn").and_then(|s| s.as_str());
                        let mut engine = IdentityEngine::new();
                        match engine.execute(IdentityCommand::LoadPrincipals(json_str.into())) {
                            Ok(_) => {
                                let reports: Vec<&RightSizingReport> = if let Some(arn) = p_filter {
                                    engine.right_sizing.iter().filter(|r| r.principal_arn.eq_ignore_ascii_case(arn)).collect()
                                } else {
                                    engine.right_sizing.iter().collect()
                                };
                                serde_json::json!({
                                    "reports_count": reports.len(),
                                    "right_sizing_reports": reports
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
                "error": { "code": -32601, "message": "Method not found" }
            }),
        };

        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
        stdout.flush()?;
    }

    Ok(())
}
