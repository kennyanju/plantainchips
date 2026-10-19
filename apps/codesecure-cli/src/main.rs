use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use codesecure::{CodeCommand, CodeEngine, IacFinding, IacPolicyEngine, ScaAndSbomEngine, SbomComponent};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "codesecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "CodeSecure: ASPM & IaC Shift-Left Static Analyzer CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan Terraform HCL, Kubernetes YAML, Dockerfiles, and CI workflows for misconfigurations
    Scan {
        /// Path to IaC files JSON snapshot
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Generate automated line-level fix patch for an IaC finding
    Autofix {
        /// Path to IaC files JSON snapshot
        #[arg(short, long)]
        input: PathBuf,

        /// Rule ID to remediate (e.g. IAC_AWS_001, IAC_K8S_001, IAC_DOCKER_001)
        #[arg(short, long)]
        rule: String,
    },

    /// Generate standard CycloneDX 1.5 Software Bill of Materials (SBOM)
    Sbom {
        /// Path to dependency components JSON file
        #[arg(short, long)]
        components: PathBuf,
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
        Some(Commands::Scan { input, format }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = CodeEngine::new();
            engine.execute(CodeCommand::LoadFiles(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine.findings.iter().any(|f| f.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::Autofix { input, rule }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = CodeEngine::new();
            engine.execute(CodeCommand::LoadFiles(json_content))?;

            let mut matched = false;
            for file in &engine.files {
                let findings = IacPolicyEngine::scan_file(file);
                for f in findings {
                    if f.rule_id.eq_ignore_ascii_case(&rule) {
                        println!("# Auto-Fix Patch for {} ({}:{})", f.rule_id, f.file_path, f.line_number);
                        if let Some(ref patch) = f.auto_fix_patch {
                            println!("{}\n", patch);
                        }
                        matched = true;
                    }
                }
            }
            if !matched {
                eprintln!("No findings matching rule '{}' to auto-fix.", rule);
                std::process::exit(1);
            }
        }
        Some(Commands::Sbom { components }) => {
            let raw_json = fs::read_to_string(&components)?;
            let comps: Vec<SbomComponent> = serde_json::from_str(&raw_json)?;
            let sbom = ScaAndSbomEngine::generate_cyclonedx(&comps);
            println!("{}", serde_json::to_string_pretty(&sbom)?);
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
    engine: &CodeEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<16} {:<32} {:<42}", "SEVERITY", "RULE ID", "LOCATION", "TITLE");
            println!("{}", "-".repeat(105));
            for f in findings {
                println!(
                    "{:<10} {:<16} {:<32} {:<42}",
                    format!("{} {:?}", f.severity.glyph(), f.severity),
                    f.rule_id,
                    f.resource_id,
                    if f.title.len() > 42 { format!("{}...", &f.title[..39]) } else { f.title.clone() }
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total IaC Findings: {}", findings.len());
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
            println!("Severity,RuleId,Location,Title,Message");
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

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for CodeSecure.
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
                        "name": "codesecure-mcp",
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
                            "name": "aspm_scan_iac_directory",
                            "description": "Scan Terraform, Kubernetes, Dockerfile, and GitHub Actions files for security flaws and hardcoded secrets",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "files_json": { "type": "string" }
                                },
                                "required": ["files_json"]
                            }
                        },
                        {
                            "name": "aspm_generate_iac_autofix",
                            "description": "Generate automated line-level fix patch for a given IaC policy rule violation",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "files_json": { "type": "string" },
                                    "rule_id": { "type": "string" }
                                },
                                "required": ["files_json", "rule_id"]
                            }
                        },
                        {
                            "name": "aspm_generate_sbom",
                            "description": "Generate CycloneDX 1.5 Software Bill of Materials (SBOM) from component list",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "components_json": { "type": "string" }
                                },
                                "required": ["components_json"]
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
                    "aspm_scan_iac_directory" => {
                        let json_str = args.get("files_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = CodeEngine::new();
                        match engine.execute(CodeCommand::LoadFiles(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "files_scanned": engine.files.len(),
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "aspm_generate_iac_autofix" => {
                        let json_str = args.get("files_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let target_rule = args.get("rule_id").and_then(|s| s.as_str()).unwrap_or("");
                        let mut engine = CodeEngine::new();
                        let _ = engine.execute(CodeCommand::LoadFiles(json_str.into()));
                        let mut patches = Vec::new();
                        for file in &engine.files {
                            let f_list = IacPolicyEngine::scan_file(file);
                            for f in f_list {
                                if f.rule_id.eq_ignore_ascii_case(target_rule) {
                                    patches.push(serde_json::json!({
                                        "file": f.file_path,
                                        "line": f.line_number,
                                        "patch": f.auto_fix_patch
                                    }));
                                }
                            }
                        }
                        serde_json::json!({
                            "rule_id": target_rule,
                            "patches": patches
                        })
                    }
                    "aspm_generate_sbom" => {
                        let comp_str = args.get("components_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        match serde_json::from_str::<Vec<SbomComponent>>(comp_str) {
                            Ok(comps) => {
                                let sbom = ScaAndSbomEngine::generate_cyclonedx(&comps);
                                serde_json::json!({ "cyclonedx_sbom": sbom })
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
