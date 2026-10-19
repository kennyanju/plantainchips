use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use netsecure::{NetCommand, NetEngine, SecurityGroup, VpcFlowRecord};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "netsecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "NetSecure: Cloud Network Security (CNS) & Zero-Trust Microsegmentation CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze VPC flow logs for unencrypted protocols and exfiltration bursts
    AnalyzeFlows {
        /// Path to VPC flow logs JSON
        #[arg(short, long)]
        flows: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Audit Security Groups for public exposure (0.0.0.0/0) and rule shadowing
    AuditRules {
        /// Path to Security Groups JSON
        #[arg(short, long)]
        security_groups: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Synthesize Zero-Trust microsegmentation policy and remediation commands
    SynthesizePolicy {
        /// Path to VPC flow logs JSON
        #[arg(short, long)]
        flows: PathBuf,

        /// Path to Security Groups JSON
        #[arg(short, long)]
        security_groups: PathBuf,
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
        Some(Commands::AnalyzeFlows { flows, format }) => {
            let json_content = fs::read_to_string(&flows)?;
            let mut engine = NetEngine::new();
            engine.execute(NetCommand::LoadFlowLogs(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::AuditRules {
            security_groups,
            format,
        }) => {
            let json_content = fs::read_to_string(&security_groups)?;
            let mut engine = NetEngine::new();
            engine.execute(NetCommand::LoadSecurityGroups(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::SynthesizePolicy {
            flows,
            security_groups,
        }) => {
            let flows_content = fs::read_to_string(&flows)?;
            let sgs_content = fs::read_to_string(&security_groups)?;

            let flow_records: Vec<VpcFlowRecord> = serde_json::from_str(&flows_content)?;
            let sgs: Vec<SecurityGroup> = serde_json::from_str(&sgs_content)?;

            let policy = NetEngine::synthesize_microsegmentation(&flow_records, &sgs);

            println!("=== Zero-Trust Kubernetes NetworkPolicy (YAML) ===");
            println!("{}\n", policy.k8s_network_policy_yaml);

            println!("=== AWS Security Group Remediation Commands ===");
            for cmd in policy.aws_sg_remediation_commands {
                println!("{}", cmd);
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
    engine: &NetEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!(
                "{:<10} {:<14} {:<34} {}",
                "SEVERITY", "RULE ID", "RESOURCE", "TITLE"
            );
            println!("{}", "-".repeat(105));
            for f in findings {
                let glyph = if f.severity == cloudsecure_types::Severity::Critical {
                    "[!]"
                } else {
                    "[/!\\]"
                };
                let display_title = if f.title.len() > 42 {
                    format!("{}...", &f.title[..39])
                } else {
                    f.title.clone()
                };
                println!(
                    "{:<10} {:<14} {:<34} {}",
                    format!("{} {:?}", glyph, f.severity),
                    f.rule_id,
                    f.resource_id,
                    display_title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total Cloud Network Security Findings: {}", findings.len());
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(findings)?);
        }
        OutputFormat::Sarif => {
            let sarif = engine.export_sarif();
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Csv => {
            println!("Severity,RuleId,Resource,Title,Message");
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

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for NetSecure.
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
                        "name": "netsecure-mcp",
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
                            "name": "cns_analyze_flow_logs",
                            "description": "Analyze VPC Flow Logs for cleartext protocols and high-volume data exfiltration bursts",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "flows_json": { "type": "string" }
                                },
                                "required": ["flows_json"]
                            }
                        },
                        {
                            "name": "cns_audit_security_groups",
                            "description": "Audit Security Group rules for public 0.0.0.0/0 database or management port exposure and rule shadowing",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "security_groups_json": { "type": "string" }
                                },
                                "required": ["security_groups_json"]
                            }
                        },
                        {
                            "name": "cns_synthesize_microsegmentation",
                            "description": "Synthesize least-privilege Zero-Trust Kubernetes NetworkPolicy YAML and Security Group revocation commands",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "flows_json": { "type": "string" },
                                    "security_groups_json": { "type": "string" }
                                },
                                "required": ["flows_json", "security_groups_json"]
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
                    "cns_analyze_flow_logs" => {
                        let flows_str = args.get("flows_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = NetEngine::new();
                        match engine.execute(NetCommand::LoadFlowLogs(flows_str.into())) {
                            Ok(_) => serde_json::json!({
                                "flows_scanned": engine.flow_records.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "cns_audit_security_groups" => {
                        let sgs_str = args.get("security_groups_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = NetEngine::new();
                        match engine.execute(NetCommand::LoadSecurityGroups(sgs_str.into())) {
                            Ok(_) => serde_json::json!({
                                "security_groups_scanned": engine.security_groups.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "cns_synthesize_microsegmentation" => {
                        let flows_str = args.get("flows_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let sgs_str = args.get("security_groups_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        match (
                            serde_json::from_str::<Vec<VpcFlowRecord>>(flows_str),
                            serde_json::from_str::<Vec<SecurityGroup>>(sgs_str),
                        ) {
                            (Ok(flows), Ok(sgs)) => {
                                let policy = NetEngine::synthesize_microsegmentation(&flows, &sgs);
                                serde_json::json!({
                                    "k8s_network_policy_yaml": policy.k8s_network_policy_yaml,
                                    "aws_sg_remediation_commands": policy.aws_sg_remediation_commands
                                })
                            }
                            _ => serde_json::json!({ "error": "Invalid flows or security groups JSON" }),
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
