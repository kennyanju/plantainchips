use clap::{Parser, Subcommand, ValueEnum};
use cloudsecure_automation::CloudSecureAppEngine;
use graphsecure::{AttackPath, ChokePoint, GraphCommand, GraphEngine};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "graphsecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "GraphSecure: Cloud Security Graph & Attack Path Simulator CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Discover multi-hop attack paths from Internet exposure to Crown Jewel assets
    Paths {
        /// Path to graph JSON snapshot file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Calculate betweenness centrality and rank choke points by breach paths severed
    ChokePoints {
        /// Path to graph JSON snapshot file
        #[arg(short, long)]
        input: PathBuf,

        /// Output formatting style
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Simulate What-If remediation by severing an edge and verifying remaining attack paths
    Simulate {
        /// Path to graph JSON snapshot file
        #[arg(short, long)]
        input: PathBuf,

        /// Edge ID to sever/remediate (e.g. edge-alb-rce, edge-role-assume)
        #[arg(short, long)]
        cut_edge: String,
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
        Some(Commands::Paths { input, format }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = GraphEngine::new();
            engine.execute(GraphCommand::LoadGraph(json_content))?;

            output_paths(&engine.paths, format, &engine)?;
            if engine.paths.iter().any(|p| p.severity == cloudsecure_types::Severity::Critical) {
                std::process::exit(1);
            }
        }
        Some(Commands::ChokePoints { input, format }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = GraphEngine::new();
            engine.execute(GraphCommand::LoadGraph(json_content))?;

            output_choke_points(&engine.choke_points, format)?;
        }
        Some(Commands::Simulate { input, cut_edge }) => {
            let json_content = fs::read_to_string(&input)?;
            let mut engine = GraphEngine::new();
            engine.execute(GraphCommand::LoadGraph(json_content))?;
            let initial_count = engine.paths.len();

            engine.execute(GraphCommand::ToggleEdge {
                edge_id: cut_edge.clone(),
                active: false,
            })?;
            let remaining_count = engine.paths.len();
            let severed = initial_count.saturating_sub(remaining_count);

            println!("What-If Remediation Simulation Result for Edge '{}':", cut_edge);
            println!("  - Initial Viable Attack Paths : {}", initial_count);
            println!("  - Attack Paths Severed        : {}", severed);
            println!("  - Remaining Attack Paths      : {}", remaining_count);
            if severed > 0 {
                let roi = (severed as f32 / initial_count as f32) * 100.0;
                println!("  - Attack Surface Reduction    : {:.1}%", roi);
            }
        }
        None => {
            eprintln!("No command provided. Run with --help or pass --mcp to start agent server.");
        }
    }

    Ok(())
}

fn output_paths(paths: &[AttackPath], format: OutputFormat, engine: &GraphEngine) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<10} {:<12} {:<6} {:<42} {:<24}", "SEVERITY", "PATH ID", "HOPS", "TITLE", "TERMINAL ASSET");
            println!("{}", "-".repeat(105));
            for p in paths {
                let term = p.hops.last().cloned().unwrap_or_default();
                println!(
                    "{:<10} {:<12} {:<6} {:<42} {:<24}",
                    format!("{} {:?}", p.severity.glyph(), p.severity),
                    p.id,
                    p.hops.len(),
                    if p.title.len() > 42 { format!("{}...", &p.title[..39]) } else { p.title.clone() },
                    term
                );
            }
            println!("{}", "-".repeat(105));
            println!("Total Viable Attack Paths: {}", paths.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(paths)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif => {
            let sarif = engine.export_sarif();
            let serialized = serde_json::to_string_pretty(&sarif)?;
            println!("{}", serialized);
        }
        OutputFormat::Csv => {
            println!("Severity,PathId,HopCount,RiskScore,HopsSequence,Title");
            for p in paths {
                println!(
                    "{:?},{},{},{:.1},\"{}\",\"{}\"",
                    p.severity, p.id, p.hops.len(), p.cumulative_risk_score, p.hops.join(" -> "), p.title
                );
            }
        }
    }
    Ok(())
}

fn output_choke_points(choke_points: &[ChokePoint], format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        OutputFormat::Table => {
            println!("{:<4} {:<18} {:<22} {:<22} {:<14} {:<10}", "RANK", "EDGE ID", "SOURCE NODE", "TARGET NODE", "PATHS SEVERED", "ROI %");
            println!("{}", "-".repeat(100));
            for (idx, cp) in choke_points.iter().enumerate() {
                println!(
                    "{:<4} {:<18} {:<22} {:<22} {:<14} {:<10}",
                    idx + 1,
                    cp.edge_id,
                    cp.source_node,
                    cp.target_node,
                    cp.paths_severed_count,
                    format!("{:.1}%", cp.roi_percentage)
                );
            }
            println!("{}", "-".repeat(100));
            println!("Total Remediation Choke Points: {}", choke_points.len());
        }
        OutputFormat::Json => {
            let serialized = serde_json::to_string_pretty(choke_points)?;
            println!("{}", serialized);
        }
        OutputFormat::Sarif => {
            eprintln!("Note: SARIF is recommended for Attack Paths. Emitting JSON representation of choke points.");
            let serialized = serde_json::to_string_pretty(choke_points)?;
            println!("{}", serialized);
        }
        OutputFormat::Csv => {
            println!("Rank,EdgeId,SourceNode,TargetNode,PathsSevered,RoiPercentage");
            for (idx, cp) in choke_points.iter().enumerate() {
                println!(
                    "{},{},{},{},{},{:.1}",
                    idx + 1, cp.edge_id, cp.source_node, cp.target_node, cp.paths_severed_count, cp.roi_percentage
                );
            }
        }
    }
    Ok(())
}

/// JSON-RPC 2.0 stdio server implementing the Model Context Protocol (MCP) for GraphSecure.
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
                        "name": "graphsecure-mcp",
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
                            "name": "graph_find_attack_paths",
                            "description": "Discover all multi-hop breach paths from Internet exposure to Crown Jewel assets",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "graph_json": { "type": "string" }
                                },
                                "required": ["graph_json"]
                            }
                        },
                        {
                            "name": "graph_compute_choke_points",
                            "description": "Compute betweenness centrality and rank choke points by number of breach paths severed",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "graph_json": { "type": "string" }
                                },
                                "required": ["graph_json"]
                            }
                        },
                        {
                            "name": "graph_simulate_remediation",
                            "description": "Simulate severing an attack path edge to calculate attack surface reduction ROI",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "graph_json": { "type": "string" },
                                    "cut_edge": { "type": "string" }
                                },
                                "required": ["graph_json", "cut_edge"]
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
                    "graph_find_attack_paths" => {
                        let json_str = args.get("graph_json").and_then(|s| s.as_str()).unwrap_or("{}");
                        let mut engine = GraphEngine::new();
                        match engine.execute(GraphCommand::LoadGraph(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "paths_count": engine.paths.len(),
                                "paths": engine.paths
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "graph_compute_choke_points" => {
                        let json_str = args.get("graph_json").and_then(|s| s.as_str()).unwrap_or("{}");
                        let mut engine = GraphEngine::new();
                        match engine.execute(GraphCommand::LoadGraph(json_str.into())) {
                            Ok(_) => serde_json::json!({
                                "choke_points_count": engine.choke_points.len(),
                                "choke_points": engine.choke_points
                            }),
                            Err(e) => serde_json::json!({ "error": e.to_string() }),
                        }
                    }
                    "graph_simulate_remediation" => {
                        let json_str = args.get("graph_json").and_then(|s| s.as_str()).unwrap_or("{}");
                        let cut_edge = args.get("cut_edge").and_then(|s| s.as_str()).unwrap_or("");
                        let mut engine = GraphEngine::new();
                        let _ = engine.execute(GraphCommand::LoadGraph(json_str.into()));
                        let before = engine.paths.len();

                        match engine.execute(GraphCommand::ToggleEdge {
                            edge_id: cut_edge.into(),
                            active: false,
                        }) {
                            Ok(_) => {
                                let after = engine.paths.len();
                                let severed = before.saturating_sub(after);
                                let roi = if before > 0 { (severed as f32 / before as f32) * 100.0 } else { 0.0 };
                                serde_json::json!({
                                    "cut_edge": cut_edge,
                                    "before_paths": before,
                                    "after_paths": after,
                                    "paths_severed": severed,
                                    "reduction_percentage": roi
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
