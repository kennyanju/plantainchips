use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use supplysecure::{SupplyCommand, SupplyEngine};

#[derive(Parser, Debug)]
#[command(name = "supplysecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "SupplySecure: Software Supply Chain Security (SSCS) CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify SLSA v1.0 build provenance and isolation levels
    VerifySlsa {
        /// Path to SLSA provenance records JSON
        #[arg(short, long)]
        provenance: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Verify Cosign cryptographic container image signatures and Rekor entries
    VerifySignature {
        /// Path to Cosign signature records JSON
        #[arg(short, long)]
        signatures: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Scan software dependencies for dependency confusion and typo-squatting
    ScanDependencies {
        /// Path to dependencies manifest JSON
        #[arg(short, long)]
        manifest: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Synthesize Kyverno admission controller ClusterPolicy YAML
    SynthesizeAdmission,
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
        Some(Commands::VerifySlsa { provenance, format }) => {
            let json_content = fs::read_to_string(&provenance)?;
            let mut engine = SupplyEngine::new();
            engine.execute(SupplyCommand::VerifyProvenance(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::VerifySignature {
            signatures,
            format,
        }) => {
            let json_content = fs::read_to_string(&signatures)?;
            let mut engine = SupplyEngine::new();
            engine.execute(SupplyCommand::VerifySignatures(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::ScanDependencies { manifest, format }) => {
            let json_content = fs::read_to_string(&manifest)?;
            let mut engine = SupplyEngine::new();
            engine.execute(SupplyCommand::ScanDependencies(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine
                .findings
                .iter()
                .any(|f| f.severity == cloudsecure_types::Severity::Critical)
            {
                std::process::exit(1);
            }
        }
        Some(Commands::SynthesizeAdmission) => {
            let policy = SupplyEngine::synthesize_admission_policy();
            println!("=== Kubernetes Kyverno ClusterPolicy (YAML) ===");
            println!("{}", policy.cluster_policy_yaml);
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
    engine: &SupplyEngine,
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
            println!("Total Supply Chain Findings: {}", findings.len());
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

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for SupplySecure.
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
                        "name": "supplysecure-mcp",
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
                            "name": "sscs_verify_slsa_provenance",
                            "description": "Verify in-toto / SLSA v1.0 build provenance and verify Level 3 builder isolation",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "provenance_json": { "type": "string" }
                                },
                                "required": ["provenance_json"]
                            }
                        },
                        {
                            "name": "sscs_verify_cosign_signatures",
                            "description": "Verify Cosign container image cryptographic signatures and Rekor transparency log proofs",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "signatures_json": { "type": "string" }
                                },
                                "required": ["signatures_json"]
                            }
                        },
                        {
                            "name": "sscs_scan_dependencies",
                            "description": "Scan software package dependencies for dependency confusion and typo-squatting risks",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "manifest_json": { "type": "string" }
                                },
                                "required": ["manifest_json"]
                            }
                        },
                        {
                            "name": "sscs_synthesize_admission_policy",
                            "description": "Synthesize Kubernetes Kyverno ClusterPolicy YAML enforcing image signatures and SLSA provenance",
                            "inputSchema": {
                                "type": "object",
                                "properties": {}
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
                    "sscs_verify_slsa_provenance" => {
                        let prov_str = args.get("provenance_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = SupplyEngine::new();
                        match engine.execute(SupplyCommand::VerifyProvenance(prov_str.into())) {
                            Ok(_) => serde_json::json!({
                                "provenance_records_scanned": engine.provenance_records.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "sscs_verify_cosign_signatures" => {
                        let sig_str = args.get("signatures_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = SupplyEngine::new();
                        match engine.execute(SupplyCommand::VerifySignatures(sig_str.into())) {
                            Ok(_) => serde_json::json!({
                                "signatures_scanned": engine.signature_records.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "sscs_scan_dependencies" => {
                        let dep_str = args.get("manifest_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = SupplyEngine::new();
                        match engine.execute(SupplyCommand::ScanDependencies(dep_str.into())) {
                            Ok(_) => serde_json::json!({
                                "dependencies_scanned": engine.dependencies.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "sscs_synthesize_admission_policy" => {
                        let policy = SupplyEngine::synthesize_admission_policy();
                        serde_json::json!({
                            "kyverno_cluster_policy_yaml": policy.cluster_policy_yaml
                        })
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
