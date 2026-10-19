use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use threatsecure::{CloudAuditEvent, ThreatCommand, ThreatEngine};

#[derive(Parser, Debug)]
#[command(name = "threatsecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "ThreatSecure: Cloud Detection & Response (CDR) CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect multi-cloud audit log events against MITRE ATT&CK Cloud techniques
    Detect {
        /// Path to CloudTrail / audit log events JSON stream
        #[arg(short, long)]
        events: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Correlate discrete audit detections into multi-stage attack incidents
    Correlate {
        /// Path to CloudTrail / audit log events JSON stream
        #[arg(short, long)]
        events: PathBuf,
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
        Some(Commands::Detect { events, format }) => {
            let json_content = fs::read_to_string(&events)?;
            let mut engine = ThreatEngine::new();
            engine.execute(ThreatCommand::LoadAuditEvents(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::Correlate { events }) => {
            let json_content = fs::read_to_string(&events)?;
            let mut engine = ThreatEngine::new();
            engine.execute(ThreatCommand::LoadAuditEvents(json_content))?;

            println!(
                "{:<12} {:<36} {:<12} {:<10} {}",
                "INCIDENT ID", "PRINCIPAL", "CONFIDENCE", "EVENTS", "TACTICS OBSERVED"
            );
            println!("{}", "-".repeat(105));
            for inc in &engine.incidents {
                let tactics_str = inc.tactics_observed.join(" -> ");
                println!(
                    "{:<12} {:<36} {:<12.2} {:<10} {}",
                    inc.incident_id, inc.principal_arn, inc.confidence_score, inc.event_count, tactics_str
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total Correlated Incidents: {}", engine.incidents.len());
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
    engine: &ThreatEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!(
                "{:<10} {:<14} {:<38} {}",
                "SEVERITY", "RULE ID", "PRINCIPAL", "TITLE"
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
                let display_principal = if f.resource_id.len() > 36 {
                    format!("{}...", &f.resource_id[..33])
                } else {
                    f.resource_id.clone()
                };
                println!(
                    "{:<10} {:<14} {:<38} {}",
                    format!("{} {:?}", glyph, f.severity),
                    f.rule_id,
                    display_principal,
                    display_title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total MITRE ATT&CK Cloud Detections: {}", findings.len());
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(findings)?);
        }
        OutputFormat::Sarif => {
            let sarif = engine.export_sarif();
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        OutputFormat::Csv => {
            println!("Severity,RuleId,Principal,Title,Message");
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

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for ThreatSecure.
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
                        "name": "threatsecure-mcp",
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
                            "name": "cdr_detect_threats",
                            "description": "Inspect multi-cloud audit log events against MITRE ATT&CK Cloud techniques (T1562, T1098, T1078, T1537, T1485)",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "events_json": { "type": "string" }
                                },
                                "required": ["events_json"]
                            }
                        },
                        {
                            "name": "cdr_correlate_kill_chains",
                            "description": "Correlate discrete audit log detections into unified multi-stage attack incidents and kill chains",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "events_json": { "type": "string" }
                                },
                                "required": ["events_json"]
                            }
                        },
                        {
                            "name": "cdr_generate_containment",
                            "description": "Generate automated cloud CLI commands to isolate compromised principals and stop exfiltration",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "events_json": { "type": "string" }
                                },
                                "required": ["events_json"]
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
                    "cdr_detect_threats" => {
                        let events_str = args.get("events_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = ThreatEngine::new();
                        match engine.execute(ThreatCommand::LoadAuditEvents(events_str.into())) {
                            Ok(_) => serde_json::json!({
                                "events_scanned": engine.events.len(),
                                "detections_count": engine.detections.len(),
                                "detections": engine.detections
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "cdr_correlate_kill_chains" => {
                        let events_str = args.get("events_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = ThreatEngine::new();
                        let _ = engine.execute(ThreatCommand::LoadAuditEvents(events_str.into()));
                        serde_json::json!({
                            "incidents_count": engine.incidents.len(),
                            "incidents": engine.incidents
                        })
                    }
                    "cdr_generate_containment" => {
                        let events_str = args.get("events_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        match serde_json::from_str::<Vec<CloudAuditEvent>>(events_str) {
                            Ok(events) => {
                                let mut actions = Vec::new();
                                for ev in &events {
                                    for det in ThreatEngine::evaluate_event(ev) {
                                        actions.push(serde_json::json!({
                                            "detection_id": det.detection_id,
                                            "principal": det.principal_arn,
                                            "action": det.containment_action
                                        }));
                                    }
                                }
                                serde_json::json!({
                                    "containment_actions_count": actions.len(),
                                    "actions": actions
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
