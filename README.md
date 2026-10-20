# PlantainChips: CloudSecure Suite

> **Thirteen security apps. One unified architecture. Rebuilt in pure Rust.**  
> An open-source, local-first Cloud-Native Application Protection Platform (CNAPP) suite inspired by `getartcraft.com` and `storytold/craft-launcher`.

[![License](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org)
[![Unit Tests](https://img.shields.io/badge/tests-79%20passed-brightgreen.svg)](tests/)
[![Release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/kennyanju/plantainchips/releases/tag/v0.1.0)
[![Documentation](https://img.shields.io/badge/docs-tutorial%20available-purple.svg)](TUTORIAL.md)

---

## Trademark & Non-Affiliation Notice

CloudSecure and its component applications (`PostureSecure`, `DataSecure`, `WorkloadSecure`, `IdentitySecure`, `CodeSecure`, `WaasSecure`, `ThreatSecure`, `GraphSecure`, `NetSecure`, `AiSecure`, `SupplySecure`, `PolicySecure`, `ComplianceSecure`, and `LauncherSecure`) are an independent, clean-room open-source project. All application names end with the descriptive suffix `-secure`.

CloudSecure is **not** affiliated with, sponsored by, authorized by, or endorsed by Palo Alto Networks, Inc., Ivanti, or any of their affiliates. All brand names and trademarks (including Prisma Cloud, Cortex, Checkov, PAN-OS, and Pulse Secure) are the property of their respective owners.

---

## Quickstart: How to Use CloudSecure

CloudSecure provides two unified ways to run every security engine:

### 1. Interactive GUI Workbench (Visual & Zero CLI)

Run and interact with all 14 applications visually in your web browser:

```bash
# On macOS, open directly in your default browser:
open web/workbench.html

# Or serve locally via HTTP:
python3 -m http.server 8000 -d web
# Visit: http://localhost:8000/workbench.html
```

- **Interactive Telemetry**: Execute scans, inspect multi-hop attack graphs, audit container layers, test prompt injection payloads, and track compliance readiness with one click.
- **Client-Side Security**: All analysis runs locally in your browser sandbox. No cloud credentials or data store contents leave your computer.
- **Export Formats**: One-click export to standard JSON or OASIS SARIF v2.1.0 for GitHub Code Scanning and Jira import.

---

### 2. Automated Terminal CLI Installation

Install all 14 standalone CLI binaries directly to `~/.cloudsecure/bin`:

```bash
# Download and install all 14 binaries:
curl -fsSL https://raw.githubusercontent.com/kennyanju/plantainchips/main/web/install.sh | sh

# Add to current terminal session:
export PATH="${HOME}/.cloudsecure/bin:${PATH}"

# Test suite catalog:
launchersecure list
```

To make `~/.cloudsecure/bin` permanently available in your shell:
```bash
echo 'export PATH="${HOME}/.cloudsecure/bin:${PATH}"' >> ~/.zshrc
source ~/.zshrc
```

---

## Step-by-Step Tutorial

Read the complete [TUTORIAL.md](TUTORIAL.md) for in-depth walkthroughs:
- **Part 1**: Tour of the 14 Visual Workbenches in `web/workbench.html`.
- **Part 2**: Running audits across CSPM, DSPM, CWPP, and AI-SPM.
- **Part 3**: Terminal CLI automation and CI/CD GitHub Actions pipelines.
- **Part 4**: Resource Query Language (RQL) grammar and interactive studio.
- **Part 5**: Connecting Claude Desktop, Cursor, and Gemini to CloudSecure via Model Context Protocol (MCP).
- **Part 6**: Executive Compliance Readiness for SOC 2, HIPAA, PCI-DSS, and ISO 27001.

---

## Suite Directory (14 Applications)

Every application compiles from a single Rust workspace with a 4-way control engine (GUI Workbench, Headless CLI, JSON-RPC, and Model Context Protocol):

| ID | Binary | Display Name | CNAPP Security Discipline | GUI Workbench | Primary Engine |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `00` | `launchersecure` | **LauncherSecure** | Suite Manager & Auto-Updater | [Open GUI](web/workbench.html?app=launchersecure) | 2-/3-column card grid, Ed25519 + SHA-256 updater |
| `01` | `posturesecure` | **PostureSecure** | CSPM (Cloud Security Posture) | [Open GUI](web/workbench.html?app=posturesecure) | Multi-cloud inventory, RQL `config from` evaluator, Terraform diffs |
| `02` | `datasecure` | **DataSecure** | DSPM (Data Classification & DDR) | [Open GUI](web/workbench.html?app=datasecure) | S3/RDS/BigQuery bucket exposure, PII/PHI regex + entropy engine |
| `03` | `workloadsecure` | **WorkloadSecure** | CWPP (Cloud Workload Protection) | [Open GUI](web/workbench.html?app=workloadsecure) | Container/VM/K8s image layer inspector, runtime baseline editor |
| `04` | `identitysecure` | **IdentitySecure** | CIEM (IAM Entitlement Management) | [Open GUI](web/workbench.html?app=identitysecure) | Effective permissions calculator (`P_eff`), blast-radius graph |
| `05` | `codesecure` | **CodeSecure** | ASPM & IaC Static Analysis | [Open GUI](web/workbench.html?app=codesecure) | HCL/CloudFormation/K8s AST scanner, CycloneDX/SPDX SBOM |
| `06` | `waassecure` | **WaasSecure** | WAAS (API & Layer-7 Firewall) | [Open GUI](web/workbench.html?app=waassecure) | OpenAPI 3.1 route tree, OWASP API Top 10 rule matrix |
| `07` | `threatsecure` | **ThreatSecure** | CDR (Cloud Detection & Response) | [Open GUI](web/workbench.html?app=threatsecure) | 120 FPS virtualized event timeline, MITRE ATT&CK Cloud matrix |
| `08` | `graphsecure` | **GraphSecure** | Attack Path Engine | [Open GUI](web/workbench.html?app=graphsecure) | GPU-instanced `wgpu` graph (`50k` nodes), toxic-path finder |
| `09` | `netsecure` | **NetSecure** | CNS (Cloud Network Security) | [Open GUI](web/workbench.html?app=netsecure) | VPC/VNet topology map, BDD reachability solver, Cilium policy generator |
| `10` | `aisecure` | **AiSecure** | AI-SPM (AI Security Posture) | [Open GUI](web/workbench.html?app=aisecure) | Model/Dataset/VectorDB lineage DAG, OWASP LLM prompt firewall |
| `11` | `supplysecure` | **SupplySecure** | Software Supply Chain Security | [Open GUI](web/workbench.html?app=supplysecure) | CI/CD pipeline attack graph, SLSA provenance & Cosign verifier |
| `12` | `policysecure` | **PolicySecure** | Policy-as-Code & RQL Studio | [Open GUI](web/workbench.html?app=policysecure) | Unified RQL parser/compiler (`config`, `event`, `network`, `iam`, `data`, `ai`) |
| `13` | `compliancesecure` | **ComplianceSecure** | Executive Compliance Command | [Open GUI](web/workbench.html?app=compliancesecure) | Cross-framework crosswalk (CIS, NIST, SOC 2, PCI-DSS, HIPAA, ISO 27001) |

---

## Connecting AI Agents (Model Context Protocol)

Every standalone CLI tool includes an integrated Model Context Protocol (MCP) server over `stdio`. Connect Claude Desktop, Cursor, or Gemini CLI by adding this configuration to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "cloudsecure-launcher": { "command": "launchersecure", "args": ["--mcp"] },
    "cloudsecure-posture": { "command": "posturesecure", "args": ["--mcp"] },
    "cloudsecure-data": { "command": "datasecure", "args": ["--mcp"] },
    "cloudsecure-workload": { "command": "workloadsecure", "args": ["--mcp"] },
    "cloudsecure-waas": { "command": "waassecure", "args": ["--mcp"] },
    "cloudsecure-code": { "command": "codesecure", "args": ["--mcp"] },
    "cloudsecure-identity": { "command": "identitysecure", "args": ["--mcp"] },
    "cloudsecure-threat": { "command": "threatsecure", "args": ["--mcp"] },
    "cloudsecure-graph": { "command": "graphsecure", "args": ["--mcp"] },
    "cloudsecure-net": { "command": "netsecure", "args": ["--mcp"] },
    "cloudsecure-aisec": { "command": "aisecure", "args": ["--mcp"] },
    "cloudsecure-supply": { "command": "supplysecure", "args": ["--mcp"] },
    "cloudsecure-policy": { "command": "policysecure", "args": ["--mcp"] },
    "cloudsecure-compliance": { "command": "compliancesecure", "args": ["--mcp"] }
  }
}
```

---

## Architectural Principles

1. **100% Pure Rust**: Zero Electron, zero Tauri, and zero heavy background runtimes. Native desktop binaries run with `< 15 MB` executable size and `< 80 MB` idle RAM.
2. **Deterministic 4-Way Control ("Built for Agents")**: Every user action is a serializable `Command` struct. The engine can be driven via interactive GUI, high-speed CLI, JSON-RPC, or as a native **Model Context Protocol (MCP)** server with offscreen screenshot rendering.
3. **Unified Resource Query Language (`cloudsecure-rql`)**: A zero-copy parser (`winnow`) supporting all 6 RQL query families across multi-cloud environments.
4. **Security Asset & Exposure Graph (`cloudsecure-graph`)**: High-performance directed graph representation (`petgraph`) saved to local SQLite (WAL) or portable `.csec` snapshots.
5. **Local-First & Read-Only Assessment**: Cloud connectors operate in read-only mode by default. Remediation playbooks emit reviewable Terraform and CLI diff patches requiring human approval before execution.

---

## Repository Documentation & Implementation Plans

- [TUTORIAL.md](TUTORIAL.md): Complete step-by-step tutorial covering GUI, CLI, RQL, MCP, and Compliance.
- [DESIGN.md](DESIGN.md): Visual design contract, technical HUD grid system, typography, and WCAG AA verified color tokens.
- [cloudsecure-master-spec.md](project-specs/cloudsecure-master-spec.md): Architectural blueprint, threat model, and 10-point Red-Team risk register.
- [cloudsecure-apps-catalog-spec.md](project-specs/cloudsecure-apps-catalog-spec.md): Deep-dive specifications for all 14 applications (data structures, UI layouts, CLI arguments, and MCP tools).
- [cloudsecure-website-and-github-spec.md](project-specs/cloudsecure-website-and-github-spec.md): Portal architecture and release pipeline.
- [cloudsecure-architecture.md](project-docs/cloudsecure-architecture.md): Cargo workspace layout, ADRs, RQL grammar, and Wasm size budgeting.
- [cloudsecure-tasklist.md](project-tasks/cloudsecure-tasklist.md): 42-task sequential implementation plan mapped across 21 specialized agency agent personas.

---

## License

This project is licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
