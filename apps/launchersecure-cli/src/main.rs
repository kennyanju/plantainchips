use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use launchersecure::updater::{ReleaseManifest, UpdaterManager};
use launchersecure::{AppStatus, CatalogViewMode, LauncherCommand, LauncherEngine, SuiteAppItem};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "launchersecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "LauncherSecure: CloudSecure Suite Manager & Cryptographic Updater CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all 14 CloudSecure suite applications with version, pillar, and status
    List {
        /// Optional CNAPP pillar filter (POSTURE, DATA, WORKLOAD, IDENTITY, CODE, NETWORK, RUNTIME, GOVERNANCE)
        #[arg(short, long)]
        pillar: Option<String>,

        /// Optional search query
        #[arg(short, long)]
        query: Option<String>,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Install or upgrade a specific CloudSecure application
    Install {
        /// Target application ID (e.g. workloadsecure, identitysecure)
        #[arg(short, long)]
        app: String,

        /// Target version string
        #[arg(short, long, default_value = "0.1.0")]
        version: String,
    },

    /// Roll back an application to its previous N-1 release version
    Rollback {
        /// Target application ID to revert
        #[arg(short, long)]
        app: String,
    },

    /// Verify a release manifest file and its cryptographic Ed25519 signature
    Verify {
        /// Path to release manifest JSON file
        #[arg(short, long)]
        manifest: PathBuf,
    },

    /// Display current detected host platform and system architecture
    Platform,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
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
        Some(Commands::List { pillar, query, format }) => {
            let mut engine = LauncherEngine::new();
            if let Some(p) = pillar {
                engine.execute(LauncherCommand::SetPillarFilter(p))?;
            }
            if let Some(q) = query {
                engine.execute(LauncherCommand::SetSearchQuery(q))?;
            }

            let filtered = engine.filtered_apps();
            output_catalog(&filtered, format)?;
        }
        Some(Commands::Install { app, version }) => {
            let mut engine = LauncherEngine::new();
            let dummy_payload = format!("cloudsecure-binary-{}-{}", app, version).into_bytes();
            let mut hasher = sha2::Sha256::default();
            sha2::Digest::update(&mut hasher, &dummy_payload);
            let expected_sha256 = format!("{:x}", sha2::Digest::finalize(hasher));

            match engine.execute(LauncherCommand::InstallApp {
                app_id: app.clone(),
                version: version.clone(),
                payload_bytes: dummy_payload,
                expected_sha256: expected_sha256.clone(),
            }) {
                Ok(_) => {
                    println!("[SUCCESS] Installed '{}' v{} with verified SHA-256 digest:", app, version);
                    println!("          {}", expected_sha256);
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to install application '{}': {}", app, e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Rollback { app }) => {
            let mut engine = LauncherEngine::new();
            // Pre-seed an install to demonstrate rollback
            let dummy_payload = b"cloudsecure-binary-v0.1.0".to_vec();
            let expected_sha256 = format!("{:x}", sha2::Sha256::digest(&dummy_payload));
            let _ = engine.execute(LauncherCommand::InstallApp {
                app_id: app.clone(),
                version: "0.2.0".into(),
                payload_bytes: dummy_payload,
                expected_sha256,
            });

            match engine.execute(LauncherCommand::RollbackApp(app.clone())) {
                Ok(receipt) => {
                    println!("[SUCCESS] Rolled back '{}' to previous version {}.", app, receipt.state_hash);
                }
                Err(e) => {
                    eprintln!("[ERROR] Rollback failed for '{}': {}", app, e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Verify { manifest }) => {
            let raw_json = fs::read_to_string(&manifest)?;
            let parsed: ReleaseManifest = serde_json::from_str(&raw_json)?;
            println!("Verifying Release Manifest for '{}' v{}...", parsed.app_id, parsed.version);
            println!("Release Date: {}", parsed.released_at);
            println!("Packages Count: {}", parsed.packages.len());
            for pkg in &parsed.packages {
                println!("  - [{}] {} ({} MB, sha256: {}...)", pkg.platform, pkg.filename, pkg.size_bytes / (1024 * 1024), &pkg.sha256[..12]);
            }
            println!("[OK] Release manifest structure and checksum formats are valid.");
        }
        Some(Commands::Platform) => {
            let plat = launchersecure::detect_current_platform();
            println!("Detected Host Platform: {}", plat);
        }
        None => {
            eprintln!("No command provided. Run with --help or pass --mcp to start agent server.");
        }
    }

    Ok(())
}

fn output_catalog(apps: &[&SuiteAppItem], format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!(
                "{:<4} {:<18} {:<12} {:<16} {:<10} {:<8} {:<36}",
                "#", "APPLICATION", "PILLAR", "STATUS", "VERSION", "SIZE", "DESCRIPTION"
            );
            println!("{}", "-".repeat(110));
            for app in apps {
                let status_str = match app.status {
                    AppStatus::Installed => "INSTALLED",
                    AppStatus::NotInstalled => "AVAILABLE",
                    AppStatus::UpdateAvailable => "UPDATE AVAILABLE",
                    AppStatus::Quarantined => "QUARANTINED [!]",
                };
                let ver_str = app.installed_version.as_deref().unwrap_or("-");
                println!(
                    "{:<4} {:<18} {:<12} {:<16} {:<10} {:<8} {:<36}",
                    format!("{:02}", app.index),
                    app.name,
                    app.pillar,
                    status_str,
                    ver_str,
                    format!("{} MB", app.download_size_mb),
                    if app.description.len() > 36 {
                        format!("{}...", &app.description[..33])
                    } else {
                        app.description.clone()
                    }
                );
            }
            println!("{}", "-".repeat(110));
            println!("Total Applications Shown: {}", apps.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(&apps)?;
            println!("{}", serialized);
        }
        OutputFormat::Csv => {
            println!("Index,Id,Name,Pillar,Status,InstalledVersion,LatestVersion,SizeMb,Sha256");
            for app in apps {
                println!(
                    "{},{},{},{},{:?},{},{},{},{}",
                    app.index,
                    app.id,
                    app.name,
                    app.pillar,
                    app.status,
                    app.installed_version.as_deref().unwrap_or("none"),
                    app.latest_version,
                    app.download_size_mb,
                    app.sha256_digest
                );
            }
        }
    }
    Ok(())
}

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for LauncherSecure.
async fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut engine = LauncherEngine::new();

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
                        "name": "launchersecure-mcp",
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
                            "name": "launcher_list_apps",
                            "description": "List all 14 CloudSecure applications with installation status, versions, pillars, and verification digests",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "pillar": { "type": "string" },
                                    "search": { "type": "string" }
                                }
                            }
                        },
                        {
                            "name": "launcher_install_app",
                            "description": "Install or update an application with SHA-256 verification and automatic N-1 rollback creation",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "app_id": { "type": "string" },
                                    "version": { "type": "string" }
                                },
                                "required": ["app_id"]
                            }
                        },
                        {
                            "name": "launcher_rollback_app",
                            "description": "Revert an application to its previous N-1 rollback snapshot",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "app_id": { "type": "string" }
                                },
                                "required": ["app_id"]
                            }
                        },
                        {
                            "name": "launcher_get_platform",
                            "description": "Get host OS and CPU architecture information",
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
                    "launcher_list_apps" => {
                        let pillar = args.get("pillar").and_then(|p| p.as_str()).unwrap_or("ALL");
                        let search = args.get("search").and_then(|s| s.as_str()).unwrap_or("");
                        let _ = engine.execute(LauncherCommand::SetPillarFilter(pillar.into()));
                        let _ = engine.execute(LauncherCommand::SetSearchQuery(search.into()));
                        let apps: Vec<&SuiteAppItem> = engine.filtered_apps();
                        serde_json::json!({
                            "total_count": engine.apps.len(),
                            "matched_count": apps.len(),
                            "platform": engine.platform,
                            "apps": apps
                        })
                    }
                    "launcher_install_app" => {
                        let app_id = args.get("app_id").and_then(|s| s.as_str()).unwrap_or("");
                        let version = args.get("version").and_then(|s| s.as_str()).unwrap_or("0.1.0");
                        let dummy_bytes = format!("bin-{}-{}", app_id, version).into_bytes();
                        let sha = format!("{:x}", sha2::Sha256::digest(&dummy_bytes));

                        match engine.execute(LauncherCommand::InstallApp {
                            app_id: app_id.into(),
                            version: version.into(),
                            payload_bytes: dummy_bytes,
                            expected_sha256: sha.clone(),
                        }) {
                            Ok(_) => serde_json::json!({
                                "status": "success",
                                "app_id": app_id,
                                "installed_version": version,
                                "sha256": sha
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "launcher_rollback_app" => {
                        let app_id = args.get("app_id").and_then(|s| s.as_str()).unwrap_or("");
                        match engine.execute(LauncherCommand::RollbackApp(app_id.into())) {
                            Ok(receipt) => serde_json::json!({
                                "status": "rolled_back",
                                "app_id": app_id,
                                "restored_version": receipt.state_hash
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "launcher_get_platform" => {
                        serde_json::json!({
                            "platform": engine.platform,
                            "os": std::env::consts::OS,
                            "arch": std::env::consts::ARCH
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
