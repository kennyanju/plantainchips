use clap::{Parser, Subcommand, ValueEnum};
use policysecure::{PolicyPack, PolicySecureEngine};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "policysecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "PolicySecure: Unified RQL and Policy-as-Code Studio CLI & Agent MCP Server")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Parse RQL query and display AST execution explain plan
    Explain {
        /// RQL query string
        #[arg(short, long)]
        query: String,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Run unit tests for a policy pack against positive and negative fixtures
    Test {
        /// Path to policy pack JSON file
        #[arg(short, long)]
        pack: PathBuf,

        /// Benchmark query evaluation speed
        #[arg(short, long)]
        benchmark: bool,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Validate policy pack schema, syntax, and framework mappings
    Validate {
        /// Path to policy pack JSON file
        #[arg(short, long)]
        pack: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Benchmark query execution across iterations
    Benchmark {
        /// RQL query string
        #[arg(short, long)]
        query: String,

        /// Number of benchmark iterations
        #[arg(short, long, default_value = "1000")]
        iterations: usize,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
    Tree,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.mcp {
        return run_mcp_server();
    }

    match cli.command {
        Some(Commands::Explain { query, format }) => {
            let plan = PolicySecureEngine::explain_query(&query);
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                }
                OutputFormat::Table | OutputFormat::Tree => {
                    println!("=== PolicySecure RQL Explain Plan ===");
                    println!("Query:    {}", plan.raw_query);
                    println!("Family:   {}", plan.family);
                    println!("Valid:    {}", plan.is_valid);
                    println!("Parse:    {} us", plan.parse_time_us);
                    if let Some(root) = &plan.ast_root {
                        println!("\nAST Execution Tree:");
                        print_explain_node(root, 0);
                    }
                    if !plan.validation_errors.is_empty() {
                        println!("\nErrors:");
                        for err in &plan.validation_errors {
                            println!("  [!] {}", err);
                        }
                    }
                }
            }
            if !plan.is_valid {
                std::process::exit(1);
            }
        }
        Some(Commands::Test { pack, benchmark, format }) => {
            let content = fs::read_to_string(&pack)?;
            let policy_pack: PolicyPack = serde_json::from_str(&content)?;
            let report = PolicySecureEngine::run_unit_tests(&policy_pack);

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Table | OutputFormat::Tree => {
                    println!("=== PolicySecure Policy Pack Test Runner ===");
                    println!("Pack:     {} (v{})", report.pack_name, report.pack_version);
                    println!("Duration: {:.3} ms", report.execution_duration_ms);
                    println!("Rules:    {} total, {} passed, {} failed\n", report.total_rules, report.passed_rules, report.failed_rules);
                    println!("{:<24} {:<10} {:<12} {:<12} STATUS", "RULE ID", "FAMILY", "PASS FIXT", "FAIL FIXT");
                    println!("{:-<75}", "");
                    for outcome in &report.results {
                        let status_str = if outcome.is_success { "[PASS]" } else { "[FAIL]" };
                        println!(
                            "{:<24} {:<10} {:>4}/{:<6} {:>4}/{:<6} {}",
                            outcome.rule_id,
                            "RQL",
                            outcome.pass_fixtures_passed,
                            outcome.pass_fixtures_total,
                            outcome.fail_fixtures_passed,
                            outcome.fail_fixtures_total,
                            status_str
                        );
                        for f in &outcome.failure_details {
                            println!("    -> Error: {}", f);
                        }
                    }
                }
            }

            if benchmark {
                println!("\n--- Benchmark Profile (1,000 iterations per rule) ---");
                for rule in &policy_pack.rules {
                    let start = std::time::Instant::now();
                    for _ in 0..1000 {
                        let _ = PolicySecureEngine::explain_query(&rule.rql_query);
                    }
                    let avg_us = start.elapsed().as_micros() as f64 / 1000.0;
                    println!("Rule {}: {:.2} us/eval", rule.id, avg_us);
                }
            }

            if report.failed_rules > 0 {
                std::process::exit(1);
            }
        }
        Some(Commands::Validate { pack, format }) => {
            let content = fs::read_to_string(&pack)?;
            let policy_pack: PolicyPack = serde_json::from_str(&content)?;
            let report = PolicySecureEngine::validate_pack(&policy_pack);

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                }
                OutputFormat::Table | OutputFormat::Tree => {
                    println!("=== PolicySecure Pack Validation ===");
                    println!("Pack:   {}", report.pack_name);
                    println!("Rules:  {}", report.rule_count);
                    println!("Valid:  {}", report.is_valid);
                    if !report.errors.is_empty() {
                        println!("\nErrors ({}):", report.errors.len());
                        for err in &report.errors {
                            println!("  [!] {}", err);
                        }
                    }
                    if !report.warnings.is_empty() {
                        println!("\nWarnings ({}):", report.warnings.len());
                        for w in &report.warnings {
                            println!("  [*] {}", w);
                        }
                    }
                }
            }

            if !report.is_valid {
                std::process::exit(1);
            }
        }
        Some(Commands::Benchmark { query, iterations }) => {
            println!("Benchmarking RQL query: '{}'", query);
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                let _ = PolicySecureEngine::explain_query(&query);
            }
            let total_dur = start.elapsed();
            let avg_us = total_dur.as_micros() as f64 / iterations as f64;
            println!("Completed {} iterations in {:.2?}", iterations, total_dur);
            println!("Average evaluation latency: {:.2} us ({:.4} ms)", avg_us, avg_us / 1000.0);
        }
        None => {
            println!("PolicySecure CLI: Use --help for available subcommands or --mcp for Model Context Protocol mode.");
        }
    }

    Ok(())
}

fn print_explain_node(node: &policysecure::RqlExplainNode, depth: usize) {
    let indent = "  ".repeat(depth);
    println!("{}{:<18} | Cost: {:.2} ms | {}", indent, node.node_type, node.expression);
    for child in &node.children {
        print_explain_node(child, depth + 1);
    }
}

fn run_mcp_server() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = stdin.lock();

    for line in reader.lines() {
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
                        "name": "policysecure-mcp",
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
                            "name": "policy_parse_and_explain_rql",
                            "description": "Parse an RQL statement and synthesize an AST execution explain plan",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "query": { "type": "string" }
                                },
                                "required": ["query"]
                            }
                        },
                        {
                            "name": "policy_run_unit_tests",
                            "description": "Execute positive and negative test fixtures against a policy pack",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "pack_json": { "type": "string" }
                                },
                                "required": ["pack_json"]
                            }
                        },
                        {
                            "name": "policy_validate_pack",
                            "description": "Validate policy pack syntax, schema compliance, and framework mappings",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "pack_json": { "type": "string" }
                                },
                                "required": ["pack_json"]
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
                    "policy_parse_and_explain_rql" => {
                        let query = args.get("query").and_then(|s| s.as_str()).unwrap_or("");
                        let plan = PolicySecureEngine::explain_query(query);
                        serde_json::to_value(&plan).unwrap_or(serde_json::json!({ "error": "Serialization failed" }))
                    }
                    "policy_run_unit_tests" => {
                        let pack_str = args.get("pack_json").and_then(|s| s.as_str()).unwrap_or("{}");
                        match serde_json::from_str::<PolicyPack>(pack_str) {
                            Ok(pack) => {
                                let report = PolicySecureEngine::run_unit_tests(&pack);
                                serde_json::to_value(&report).unwrap_or(serde_json::json!({ "error": "Serialization failed" }))
                            }
                            Err(e) => serde_json::json!({ "error": format!("Invalid pack JSON: {}", e) }),
                        }
                    }
                    "policy_validate_pack" => {
                        let pack_str = args.get("pack_json").and_then(|s| s.as_str()).unwrap_or("{}");
                        match serde_json::from_str::<PolicyPack>(pack_str) {
                            Ok(pack) => {
                                let report = PolicySecureEngine::validate_pack(&pack);
                                serde_json::to_value(&report).unwrap_or(serde_json::json!({ "error": "Serialization failed" }))
                            }
                            Err(e) => serde_json::json!({ "error": format!("Invalid pack JSON: {}", e) }),
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
                                "text": serde_json::to_string_pretty(&tool_result)?
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

        let resp_str = serde_json::to_string(&response)?;
        writeln!(stdout, "{}", resp_str)?;
        stdout.flush()?;
    }

    Ok(())
}
