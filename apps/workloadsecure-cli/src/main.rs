use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use workloadsecure::{
    CveVulnerability, KubernetesHardeningSynthesizer, RuntimeAnomaly, WorkloadCommand, WorkloadEngine,
};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "workloadsecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "WorkloadSecure: CWPP Container X-Ray & Runtime Protection CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect OCI container images for CVE vulnerabilities, layer attribution, and secret leaks
    Scan {
        /// Path to container image snapshot JSON file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Evaluate container runtime event stream against behavioral security baseline
    Runtime {
        /// Path to runtime events JSON stream file
        #[arg(short, long)]
        events: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Synthesize production-grade hardened Kubernetes SecurityContext and SeccompProfile YAML
    Harden {
        /// Container or workload name
        #[arg(short, long, default_value = "workload")]
        container_name: String,
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
            let mut engine = WorkloadEngine::new();
            engine.execute(WorkloadCommand::LoadImages(json_content))?;

            output_vulnerabilities(&engine.vulnerabilities, format, &engine)?;
            if engine.vulnerabilities.iter().any(|v| v.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::Runtime { events, format }) => {
            let json_content = fs::read_to_string(&events)?;
            let mut engine = WorkloadEngine::new();
            engine.execute(WorkloadCommand::LoadRuntimeEvents(json_content))?;

            output_anomalies(&engine.runtime_anomalies, format)?;
            if engine.runtime_anomalies.iter().any(|a| a.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::Harden { container_name }) => {
            let yaml = KubernetesHardeningSynthesizer::synthesize_security_context(&container_name);
            println!("{}", yaml);
        }
        None => {
            eprintln!("No command provided. Run with --help or pass --mcp to start agent server.");
        }
    }

    Ok(())
}

fn output_vulnerabilities(
    vulns: &[CveVulnerability],
    format: OutputFormat,
    engine: &WorkloadEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<18} {:<16} {:<12} {:<6} {:<6} {:<30}", "SEVERITY", "CVE ID", "PACKAGE", "VERSION", "CVSS", "LAYER", "TITLE");
            println!("{}", "-".repeat(105));
            for v in vulns {
                println!(
                    "{:<10} {:<18} {:<16} {:<12} {:<6} {:<6} {:<30}",
                    format!("{} {:?}", v.severity.glyph(), v.severity),
                    v.cve_id,
                    v.package_name,
                    v.installed_version,
                    format!("{:.1}", v.cvss_score),
                    format!("L{}", v.introduced_in_layer_index),
                    if v.title.len() > 30 { format!("{}...", &v.title[..27]) } else { v.title.clone() }
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total CVE Vulnerabilities: {}", vulns.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(vulns)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif => {
            let sarif = engine.export_sarif();
            let serialized = serde_json::to_string_pretty(&sarif)?;
            println!("{}", serialized);
        }
        OutputFormat::Csv => {
            println!("Severity,CveId,Package,Version,FixedVersion,Cvss,LayerIndex,Title");
            for v in vulns {
                println!(
                    "{:?},{},{},{},{},{:.1},{},\"{}\"",
                    v.severity, v.cve_id, v.package_name, v.installed_version,
                    v.fixed_version.as_deref().unwrap_or("none"), v.cvss_score, v.introduced_in_layer_index, v.title
                );
            }
        }
    }
    Ok(())
}

fn output_anomalies(
    anomalies: &[RuntimeAnomaly],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<14} {:<24} {:<40}", "SEVERITY", "RULE ID", "CONTAINER ID", "ANOMALY TITLE");
            println!("{}", "-".repeat(95));
            for a in anomalies {
                println!(
                    "{:<10} {:<14} {:<24} {:<40}",
                    format!("{} {:?}", a.severity.glyph(), a.severity),
                    a.rule_id,
                    a.container_id,
                    if a.title.len() > 40 { format!("{}...", &a.title[..37]) } else { a.title.clone() }
                );
            }
            println!("{}", "-".repeat(95));
            println!("Total Runtime Behavioral Anomalies: {}", anomalies.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(anomalies)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif | OutputFormat::Csv => {
            println!("Severity,RuleId,ContainerId,Title,Description");
            for a in anomalies {
                println!("{:?},{},{},\"{}\",\"{}\"", a.severity, a.rule_id, a.container_id, a.title, a.description);
            }
        }
    }
    Ok(())
}

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for WorkloadSecure.
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
                        "name": "workloadsecure-mcp",
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
                            "name": "cwpp_scan_oci_image",
                            "description": "Scan OCI/Docker container image layers for package CVEs and leaked secrets",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "image_json": { "type": "string" }
                                },
                                "required": ["image_json"]
                            }
                        },
                        {
                            "name": "cwpp_analyze_runtime_events",
                            "description": "Analyze container runtime syscall and process execution event stream",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "events_json": { "type": "string" }
                                },
                                "required": ["events_json"]
                            }
                        },
                        {
                            "name": "cwpp_generate_seccomp_profile",
                            "description": "Generate hardened Kubernetes SecurityContext and SeccompProfile YAML for a workload",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "workload_name": { "type": "string" }
                                },
                                "required": ["workload_name"]
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
                    "cwpp_scan_oci_image" => {
                        let json_str = args.get("image_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = WorkloadEngine::new();
                        match engine.execute(WorkloadCommand::LoadImages(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "images_scanned": engine.images.len(),
                                "vulnerabilities_count": engine.vulnerabilities.len(),
                                "vulnerabilities": engine.vulnerabilities,
                                "findings_count": engine.findings.len()
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "cwpp_analyze_runtime_events" => {
                        let json_str = args.get("events_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = WorkloadEngine::new();
                        match engine.execute(WorkloadCommand::LoadRuntimeEvents(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "anomalies_count": engine.runtime_anomalies.len(),
                                "anomalies": engine.runtime_anomalies
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "cwpp_generate_seccomp_profile" => {
                        let w_name = args.get("workload_name").and_then(|s| s.as_str()).unwrap_or("workload");
                        let yaml = KubernetesHardeningSynthesizer::synthesize_security_context(w_name);
                        serde_json::json!({
                            "workload_name": w_name,
                            "kubernetes_yaml": yaml
                        })
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
