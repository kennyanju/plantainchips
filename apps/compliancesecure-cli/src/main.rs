use clap::{Parser, Subcommand, ValueEnum};
use compliancesecure::{
    AuditBundleExporter, ComplianceFramework, IngestedPostureFinding, UnifiedPostureAggregator,
};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "compliancesecure-cli")]
#[command(version = "0.1.0")]
#[command(about = "ComplianceSecure: Executive Command Center & Multi-Framework Audit Exporter CLI & MCP")]
struct Cli {
    /// Launch in Model Context Protocol (MCP) server mode over stdio for AI agents
    #[arg(long)]
    mcp: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Ingest posture findings across modules and summarize multi-framework audit readiness
    Aggregate {
        /// Path to findings JSON or .csec snapshot
        #[arg(short, long)]
        snapshot: PathBuf,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Display Prioritized Top-10 Breach-Stopping Remediation Queue ranked by blast-radius reduction
    TopRemediations {
        /// Path to findings JSON or .csec snapshot
        #[arg(short, long)]
        snapshot: PathBuf,

        /// Max number of ranked remediations to output
        #[arg(short, long, default_value = "10")]
        limit: usize,

        /// Output formatting style
        #[arg(short = 'o', long, default_value = "table")]
        format: OutputFormat,
    },

    /// Compile and export signed multi-format audit package for a specific framework
    ExportAudit {
        /// Path to findings JSON or .csec snapshot
        #[arg(short, long)]
        snapshot: PathBuf,

        /// Compliance framework (soc2, iso27001, pci, hipaa, nist, fedramp)
        #[arg(short, long, default_value = "soc2")]
        framework: String,

        /// Organization name for audit attestations
        #[arg(long, default_value = "Acme Cloud Infrastructure")]
        organization: String,

        /// Output directory to export audit package files
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OutputFormat {
    Table,
    Json,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.mcp {
        return run_mcp_server();
    }

    match cli.command {
        Some(Commands::Aggregate { snapshot, format }) => {
            let content = fs::read_to_string(&snapshot)?;
            let findings: Vec<IngestedPostureFinding> = serde_json::from_str(&content)?;

            let mut agg = UnifiedPostureAggregator::new();
            agg.ingest_findings(findings);

            let frameworks = [
                ComplianceFramework::Soc2Type2,
                ComplianceFramework::Iso27001_2022,
                ComplianceFramework::PciDssV4,
                ComplianceFramework::HipaaSecurity,
                ComplianceFramework::NistCsf2,
                ComplianceFramework::FedrampModerate,
            ];

            let summaries: Vec<_> = frameworks.iter().map(|&fw| agg.evaluate_framework(fw)).collect();

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&summaries)?);
                }
                OutputFormat::Table => {
                    println!("=== ComplianceSecure: Multi-Framework Executive Readiness ===");
                    println!("Total Ingested Cross-Pillar Findings: {}\n", agg.findings.len());
                    println!("{:<12} {:<42} {:<8} {:<8} {:<12} CRIT / HIGH", "FRAMEWORK", "TITLE", "PASSED", "FAILED", "READINESS");
                    println!("{:-<92}", "");
                    for s in &summaries {
                        println!(
                            "{:<12} {:<42} {:>3}/{:<4} {:>3}/{:<4} {:>5.1}%      {} / {}",
                            s.framework.to_uppercase(),
                            s.display_title,
                            s.passed_controls,
                            s.total_controls,
                            s.failed_controls,
                            s.total_controls,
                            s.readiness_percentage,
                            s.critical_findings,
                            s.high_findings
                        );
                    }
                }
            }
        }
        Some(Commands::TopRemediations { snapshot, limit, format }) => {
            let content = fs::read_to_string(&snapshot)?;
            let findings: Vec<IngestedPostureFinding> = serde_json::from_str(&content)?;

            let mut agg = UnifiedPostureAggregator::new();
            agg.ingest_findings(findings);

            let remediations = agg.prioritize_remediations();
            let limited: Vec<_> = remediations.into_iter().take(limit).collect();

            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&limited)?);
                }
                OutputFormat::Table => {
                    println!("=== Prioritized Top-{} Breach-Stopping Remediation Queue ===", limit);
                    println!("Ranked by cross-pillar blast-radius reduction across all 12 CloudSecure modules:\n");
                    println!("{:<6} {:<14} {:<10} {:<12} TITLE & REMEDIATION", "RANK", "MODULE", "SEVERITY", "BLAST RED.");
                    println!("{:-<90}", "");
                    for r in &limited {
                        println!(
                            "#{:<5} {:<14} {:<10} {:>5.1} pts    {}",
                            r.rank,
                            r.source_module,
                            r.severity.as_str(),
                            r.blast_radius_reduction_score,
                            r.title
                        );
                        println!("       Resource:    {}", r.resource_id);
                        println!("       Remediation: {}\n", r.remediation_command);
                    }
                }
            }
        }
        Some(Commands::ExportAudit { snapshot, framework, organization, out }) => {
            let content = fs::read_to_string(&snapshot)?;
            let findings: Vec<IngestedPostureFinding> = serde_json::from_str(&content)?;

            let fw = ComplianceFramework::parse_code(&framework)
                .ok_or_else(|| format!("Unknown compliance framework '{}'. Valid choices: soc2, iso27001, pci, hipaa, nist, fedramp", framework))?;

            let mut agg = UnifiedPostureAggregator::new();
            agg.ingest_findings(findings);

            let bundle = agg.compile_bundle(fw, &organization);

            if let Some(out_dir) = out {
                fs::create_dir_all(&out_dir)?;

                let md_report = AuditBundleExporter::to_markdown(&bundle);
                let csv_matrix = AuditBundleExporter::to_csv(&bundle);
                let json_manifest = serde_json::to_string_pretty(&bundle)?;

                fs::write(out_dir.join("AUDIT_REPORT.md"), &md_report)?;
                fs::write(out_dir.join("audit-bundle.json"), &json_manifest)?;
                fs::write(out_dir.join("controls.csv"), &csv_matrix)?;

                let mut checksums = String::new();
                use sha2::{Digest, Sha256};
                checksums.push_str(&format!("{:x}  AUDIT_REPORT.md\n", Sha256::digest(md_report.as_bytes())));
                checksums.push_str(&format!("{:x}  audit-bundle.json\n", Sha256::digest(json_manifest.as_bytes())));
                checksums.push_str(&format!("{:x}  controls.csv\n", Sha256::digest(csv_matrix.as_bytes())));
                fs::write(out_dir.join("sha256sums.txt"), checksums)?;

                println!("Successfully exported signed audit evidence bundle to: {}", out_dir.display());
                println!("  -> AUDIT_REPORT.md   (Executive summary & remediation queue)");
                println!("  -> audit-bundle.json (Deterministic machine-readable ledger)");
                println!("  -> controls.csv      (Control status matrix)");
                println!("  -> sha256sums.txt    (Cryptographic integrity manifest)");
                println!("Bundle SHA-256: {}", bundle.manifest_sha256);
            } else {
                let md = AuditBundleExporter::to_markdown(&bundle);
                println!("{}", md);
            }
        }
        None => {
            println!("ComplianceSecure CLI: Use --help for subcommands or --mcp for Model Context Protocol mode.");
        }
    }

    Ok(())
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
                        "name": "compliancesecure-mcp",
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
                            "name": "pulse_aggregate_posture",
                            "description": "Ingest cross-pillar findings and calculate executive multi-framework compliance scores",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "findings_json": { "type": "string" }
                                },
                                "required": ["findings_json"]
                            }
                        },
                        {
                            "name": "pulse_prioritize_remediations",
                            "description": "Rank Prioritized Top-10 Breach-Stopping Remediation Queue by blast-radius reduction",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "findings_json": { "type": "string" },
                                    "limit": { "type": "integer" }
                                },
                                "required": ["findings_json"]
                            }
                        },
                        {
                            "name": "pulse_export_compliance_bundle",
                            "description": "Compile deterministically sealed audit evidence bundle for SOC 2, ISO 27001, PCI-DSS, or HIPAA",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "findings_json": { "type": "string" },
                                    "framework": { "type": "string" },
                                    "organization": { "type": "string" }
                                },
                                "required": ["findings_json", "framework"]
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
                    "pulse_aggregate_posture" => {
                        let f_str = args.get("findings_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        match serde_json::from_str::<Vec<IngestedPostureFinding>>(f_str) {
                            Ok(findings) => {
                                let mut agg = UnifiedPostureAggregator::new();
                                agg.ingest_findings(findings);
                                let frameworks = [
                                    ComplianceFramework::Soc2Type2,
                                    ComplianceFramework::Iso27001_2022,
                                    ComplianceFramework::PciDssV4,
                                    ComplianceFramework::HipaaSecurity,
                                    ComplianceFramework::NistCsf2,
                                    ComplianceFramework::FedrampModerate,
                                ];
                                let summaries: Vec<_> = frameworks.iter().map(|&fw| agg.evaluate_framework(fw)).collect();
                                serde_json::to_value(&summaries).unwrap_or(serde_json::json!({ "error": "Serialization failed" }))
                            }
                            Err(e) => serde_json::json!({ "error": format!("Invalid findings JSON: {}", e) }),
                        }
                    }
                    "pulse_prioritize_remediations" => {
                        let f_str = args.get("findings_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let limit = args.get("limit").and_then(|l| l.as_u64()).unwrap_or(10) as usize;
                        match serde_json::from_str::<Vec<IngestedPostureFinding>>(f_str) {
                            Ok(findings) => {
                                let mut agg = UnifiedPostureAggregator::new();
                                agg.ingest_findings(findings);
                                let rems: Vec<_> = agg.prioritize_remediations().into_iter().take(limit).collect();
                                serde_json::to_value(&rems).unwrap_or(serde_json::json!({ "error": "Serialization failed" }))
                            }
                            Err(e) => serde_json::json!({ "error": format!("Invalid findings JSON: {}", e) }),
                        }
                    }
                    "pulse_export_compliance_bundle" => {
                        let f_str = args.get("findings_json").and_then(|s| s.as_str()).unwrap_or("[]");
                        let fw_code = args.get("framework").and_then(|s| s.as_str()).unwrap_or("soc2");
                        let org = args.get("organization").and_then(|s| s.as_str()).unwrap_or("Acme Corp");

                        match (serde_json::from_str::<Vec<IngestedPostureFinding>>(f_str), ComplianceFramework::parse_code(fw_code)) {
                            (Ok(findings), Some(fw)) => {
                                let mut agg = UnifiedPostureAggregator::new();
                                agg.ingest_findings(findings);
                                let bundle = agg.compile_bundle(fw, org);
                                serde_json::to_value(&bundle).unwrap_or(serde_json::json!({ "error": "Serialization failed" }))
                            }
                            (Err(e), _) => serde_json::json!({ "error": format!("Invalid findings JSON: {}", e) }),
                            (_, None) => serde_json::json!({ "error": format!("Unknown framework code: {}", fw_code) }),
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
