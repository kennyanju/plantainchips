use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use aisecure::{AiAsset, AiCommand, AiEngine, AiSecurityFinding, PromptInspectionRecord};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "aisecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "AiSecure: AI Security Posture Management (AI-SPM) CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Audit AI deployment assets, vector databases, and agent tools against OWASP Top 10 for LLMs
    AuditPosture {
        /// Path to AI deployment inventory JSON
        #[arg(short, long)]
        inventory: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Inspect prompts for direct and indirect prompt injection jailbreaks
    InspectPrompts {
        /// Path to prompt records JSON
        #[arg(short, long)]
        prompts: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Synthesize Cloudflare AI Gateway policies and input/output guardrails
    SynthesizeGuardrails {
        /// Path to AI deployment inventory JSON
        #[arg(short, long)]
        inventory: PathBuf,

        /// Path to prompt records JSON (optional)
        #[arg(short, long)]
        prompts: Option<PathBuf>,
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
        Some(Commands::AuditPosture { inventory, format }) => {
            let json_content = fs::read_to_string(&inventory)?;
            let mut engine = AiEngine::new();
            engine.execute(AiCommand::LoadInventory(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::InspectPrompts { prompts, format }) => {
            let json_content = fs::read_to_string(&prompts)?;
            let mut engine = AiEngine::new();
            engine.execute(AiCommand::InspectPrompts(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::SynthesizeGuardrails { inventory, prompts }) => {
            let inv_content = fs::read_to_string(&inventory)?;
            let assets: Vec<AiAsset> = serde_json::from_str(&inv_content)?;

            let mut all_findings = Vec::new();
            for a in &assets {
                all_findings.extend(AiEngine::evaluate_asset(a));
            }

            if let Some(p_path) = prompts {
                let p_content = fs::read_to_string(&p_path)?;
                let p_records: Vec<PromptInspectionRecord> = serde_json::from_str(&p_content)?;
                for p in &p_records {
                    all_findings.extend(AiEngine::inspect_prompt(p));
                }
            }

            let guardrails = AiEngine::synthesize_guardrails(&all_findings);

            println!("=== Cloudflare AI Gateway Configuration (JSON) ===");
            println!("{}\n", guardrails.cloudflare_ai_gateway_json);

            println!("=== Active Input Guardrail Rules ===");
            for r in &guardrails.input_guardrail_rules {
                println!("- {}", r);
            }
            println!("\n=== Active Output Guardrail Rules ===");
            for r in &guardrails.output_guardrail_rules {
                println!("- {}", r);
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
    engine: &AiEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!(
                "{:<10} {:<16} {:<32} {}",
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
                    "{:<10} {:<16} {:<32} {}",
                    format!("{} {:?}", glyph, f.severity),
                    f.rule_id,
                    f.resource_id,
                    display_title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total AI Security Findings: {}", findings.len());
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

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for AiSecure.
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
                        "name": "aisecure-mcp",
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
                            "name": "aispm_audit_inventory",
                            "description": "Audit AI models, vector databases, model weights storage, and agent tools for OWASP LLM vulnerabilities",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "inventory_json": { "type": "string" }
                                },
                                "required": ["inventory_json"]
                            }
                        },
                        {
                            "name": "aispm_inspect_prompts",
                            "description": "Inspect prompt text for direct and indirect prompt injection jailbreak attacks",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "prompts_json": { "type": "string" }
                                },
                                "required": ["prompts_json"]
                            }
                        },
                        {
                            "name": "aispm_synthesize_guardrails",
                            "description": "Synthesize Cloudflare AI Gateway routing and input/output guardrail policies",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "inventory_json": { "type": "string" },
                                    "prompts_json": { "type": "string" }
                                },
                                "required": ["inventory_json"]
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
                    "aispm_audit_inventory" => {
                        let inv_str = args.get("inventory_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = AiEngine::new();
                        match engine.execute(AiCommand::LoadInventory(inv_str.into())) {
                            Ok(_) => serde_json::json!({
                                "assets_scanned": engine.assets.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "aispm_inspect_prompts" => {
                        let p_str = args.get("prompts_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = AiEngine::new();
                        match engine.execute(AiCommand::InspectPrompts(p_str.into())) {
                            Ok(_) => serde_json::json!({
                                "prompts_scanned": engine.prompts.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "aispm_synthesize_guardrails" => {
                        let inv_str = args.get("inventory_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let p_str = args.get("prompts_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        match serde_json::from_str::<Vec<AiAsset>>(inv_str) {
                            Ok(assets) => {
                                let mut all_findings = Vec::new();
                                for a in &assets {
                                    all_findings.extend(AiEngine::evaluate_asset(a));
                                }
                                if let Ok(prompts) = serde_json::from_str::<Vec<PromptInspectionRecord>>(p_str) {
                                    for p in &prompts {
                                        all_findings.extend(AiEngine::inspect_prompt(p));
                                    }
                                }
                                let guardrails = AiEngine::synthesize_guardrails(&all_findings);
                                serde_json::json!({
                                    "cloudflare_ai_gateway_json": guardrails.cloudflare_ai_gateway_json,
                                    "input_guardrail_rules": guardrails.input_guardrail_rules,
                                    "output_guardrail_rules": guardrails.output_guardrail_rules
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
