use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use cloudsecure_types::Finding;
use datasecure::{ClassificationCategory, DataCommand, DataEngine, DataStore};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "datasecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "DataSecure: 100% Pure Rust DSPM & DDR Engine CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan and classify data stores for PII, PCI, secrets, and shadow assets
    Scan {
        /// Path to JSON data store inventory file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,

        /// Optional classification category filter (PII, PCI, SECRET, PHI, FINANCIAL)
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Run Data Detection and Response (DDR) rules to flag public exposure and shadow replicas
    Ddr {
        /// Path to JSON data store inventory file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Generate deterministic Terraform HCL patch to lock down an exposed data store
    Remediate {
        /// Target data store name
        #[arg(short, long)]
        store_name: String,
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
        Some(Commands::Scan { input, format, category }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = DataEngine::new();
            engine.execute(DataCommand::IngestStores(json_content))?;

            let category_filter = category.map(|c| c.to_uppercase());
            output_stores(&engine.stores, format, category_filter.as_deref())?;
        }
        Some(Commands::Ddr { input, format }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = DataEngine::new();
            engine.execute(DataCommand::IngestStores(json_content))?;

            output_findings(&engine.findings, format, &engine)?;
            if engine.findings.iter().any(|f| f.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::Remediate { store_name }) => {
            let hcl = generate_remediation_hcl(&store_name);
            println!("# DataSecure Automated Remediation for '{}'\n{}", store_name, hcl);
        }
        None => {
            eprintln!("No command provided. Run with --help or pass --mcp to start agent server.");
        }
    }

    Ok(())
}

fn generate_remediation_hcl(store_name: &str) -> String {
    format!(
        r#"# Revoke public exposure and enforce encryption on {}
resource "aws_s3_bucket_public_access_block" "{}_block" {{
  bucket = "{}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "{}_encryption" {{
  bucket = "{}"
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "aws:kms"
    }}
  }}
}}"#,
        store_name, store_name, store_name, store_name, store_name
    )
}

fn output_stores(
    stores: &[DataStore],
    format: OutputFormat,
    category_filter: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!(
                "{:<24} {:<16} {:<8} {:<12} {:<10} {:<30}",
                "DATA STORE", "TYPE", "PUBLIC", "ENCRYPTED", "HITS", "CLASSIFICATIONS"
            );
            println!("{}", "-".repeat(105));
            for s in stores {
                let matches: Vec<&str> = s
                    .classifications
                    .iter()
                    .filter(|c| {
                        if let Some(cf) = category_filter {
                            format!("{:?}", c.category).to_uppercase() == cf
                        } else {
                            true
                        }
                    })
                    .map(|c| c.rule_name.as_str())
                    .collect();

                let summary = if matches.is_empty() {
                    "None".to_string()
                } else {
                    matches.join(", ")
                };

                println!(
                    "{:<24} {:<16} {:<8} {:<12} {:<10} {:<30}",
                    s.name,
                    format!("{:?}", s.store_type),
                    if s.is_public { "YES [!]" } else { "NO" },
                    if s.encryption_enabled { "YES" } else { "NO [!]" },
                    s.classifications.len(),
                    summary
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total Data Stores: {}", stores.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(stores)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif => {
            eprintln!("Note: SARIF is recommended for DDR findings. Emitting JSON representation of stores.");
            let serialized = serde_json::to_string_pretty(stores)?;
            println!("{}", serialized);
        }
        OutputFormat::Csv => {
            println!("Name,StoreType,Provider,IsPublic,EncryptionEnabled,ClassificationHits");
            for s in stores {
                let hits: Vec<String> = s.classifications.iter().map(|c| c.rule_name.clone()).collect();
                println!(
                    "{},{:?},{:?},{},{},\"{}\"",
                    s.name,
                    s.store_type,
                    s.provider,
                    s.is_public,
                    s.encryption_enabled,
                    hits.join(";")
                );
            }
        }
    }
    Ok(())
}

fn output_findings(
    findings: &[Finding],
    format: OutputFormat,
    engine: &DataEngine,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<18} {:<28} {:<40}", "SEVERITY", "RULE ID", "RESOURCE", "TITLE");
            println!("{}", "-".repeat(105));
            for f in findings {
                println!(
                    "{:<10} {:<18} {:<28} {:<40}",
                    format!("{} {:?}", f.severity.glyph(), f.severity),
                    f.rule_id,
                    f.resource_id,
                    f.title
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total DDR Findings: {}", findings.len());
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

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for DSPM & DDR.
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
                        "name": "datasecure-mcp",
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
                            "name": "dspm_scan_datastore",
                            "description": "Scan and classify data stores for sensitive PII, PCI, credentials, and evaluate DDR risk",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "datastore_json": { "type": "string" }
                                },
                                "required": ["datastore_json"]
                            }
                        },
                        {
                            "name": "dspm_list_exposed_pii",
                            "description": "List data stores with public access containing sensitive classified records",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "datastore_json": { "type": "string" }
                                },
                                "required": ["datastore_json"]
                            }
                        },
                        {
                            "name": "dspm_evaluate_ddr_events",
                            "description": "Evaluate Data Detection and Response (DDR) findings on cloud data stores",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "datastore_json": { "type": "string" }
                                },
                                "required": ["datastore_json"]
                            }
                        },
                        {
                            "name": "dspm_generate_remediation",
                            "description": "Generate Terraform HCL patch to lock down exposed or unencrypted data stores",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "store_name": { "type": "string" }
                                },
                                "required": ["store_name"]
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
                    "dspm_scan_datastore" => {
                        let json_str = args.get("datastore_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = DataEngine::new();
                        match engine.execute(DataCommand::IngestStores(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "stores_scanned": engine.stores.len(),
                                "findings_count": engine.findings.len(),
                                "stores": engine.stores
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "dspm_list_exposed_pii" => {
                        let json_str = args.get("datastore_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = DataEngine::new();
                        match engine.execute(DataCommand::IngestStores(json_str.into())) {
                            Ok(_) => {
                                let exposed: Vec<&DataStore> = engine
                                    .stores
                                    .iter()
                                    .filter(|s| s.is_public && !s.classifications.is_empty())
                                    .collect();
                                serde_json::json!({
                                    "exposed_count": exposed.len(),
                                    "exposed_stores": exposed
                                })
                            }
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "dspm_evaluate_ddr_events" => {
                        let json_str = args.get("datastore_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let mut engine = DataEngine::new();
                        match engine.execute(DataCommand::IngestStores(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "findings_count": engine.findings.len(),
                                "findings": engine.findings
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "dspm_generate_remediation" => {
                        let store_name = args.get("store_name").and_then(|s| s.as_str()).unwrap_or("target_store");
                        let patch = generate_remediation_hcl(store_name);
                        serde_json::json!({
                            "store_name": store_name,
                            "terraform_patch": patch
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
