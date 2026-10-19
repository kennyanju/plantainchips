# PlantainChips: CloudSecure Suite

> **Thirteen security apps. One unified architecture. Rebuilt in pure Rust.**  
> An open-source, local-first Cloud-Native Application Protection Platform (CNAPP) suite inspired by `getartcraft.com` and `storytold/craft-launcher`.

---

## Trademark & Non-Affiliation Notice

CloudSecure and its component applications (`PostureSecure`, `DataSecure`, `WorkloadSecure`, `IdentitySecure`, `CodeSecure`, `WaasSecure`, `ThreatSecure`, `GraphSecure`, `NetSecure`, `AiSecure`, `SupplySecure`, `PolicySecure`, `ComplianceSecure`, and `LauncherSecure`) are an independent, clean-room open-source project. All application names end with the descriptive suffix `-secure`.

CloudSecure is **not** affiliated with, sponsored by, authorized by, or endorsed by Palo Alto Networks, Inc., Ivanti, or any of their affiliates. All brand names and trademarks (including Prisma Cloud, Cortex, Checkov, PAN-OS, and Pulse Secure) are the property of their respective owners.

---

## Suite Directory (14 Applications)

Every application compiles from a single Rust workspace (`egui` 0.36 + `eframe` + `wgpu`) to **macOS**, **Windows**, **Linux**, **FreeBSD**, and browser **WebAssembly (`wasm32-unknown-unknown`)** with a 4-way control engine (GUI, CLI, JSON-RPC, and Model Context Protocol):

| ID | Binary | Display Name | CNAPP Security Discipline | Primary Engine |
| :--- | :--- | :--- | :--- | :--- |
| `00` | `launchersecure` | **LauncherSecure** | Suite Manager & Auto-Updater | 2-/3-column card grid, Ed25519 + SHA-256 updater |
| `01` | `posturesecure` | **PostureSecure** | CSPM (Cloud Security Posture) | Multi-cloud inventory, RQL `config from` evaluator, Terraform diffs |
| `02` | `datasecure` | **DataSecure** | DSPM (Data Classification & DDR) | S3/RDS/BigQuery bucket exposure, PII/PHI regex + entropy engine |
| `03` | `workloadsecure` | **WorkloadSecure** | CWPP (Cloud Workload Protection) | Container/VM/K8s image layer inspector, runtime baseline editor |
| `04` | `identitysecure` | **IdentitySecure** | CIEM (IAM Entitlement Management) | Effective permissions calculator (`P_eff`), blast-radius graph |
| `05` | `codesecure` | **CodeSecure** | ASPM & IaC Static Analysis | HCL/CloudFormation/K8s AST scanner, CycloneDX/SPDX SBOM |
| `06` | `waassecure` | **WaasSecure** | WAAS (API & Layer-7 Firewall) | OpenAPI 3.1 route tree, OWASP API Top 10 rule matrix |
| `07` | `threatsecure` | **ThreatSecure** | CDR (Cloud Detection & Response) | 120 FPS virtualized event timeline, MITRE ATT&CK Cloud matrix |
| `08` | `graphsecure` | **GraphSecure** | Attack Path Engine | GPU-instanced `wgpu` graph (`50k` nodes), toxic-path finder |
| `09` | `netsecure` | **NetSecure** | CNS (Cloud Network Security) | VPC/VNet topology map, BDD reachability solver, Cilium policy generator |
| `10` | `aisecure` | **AiSecure** | AI-SPM (AI Security Posture) | Model/Dataset/VectorDB lineage DAG, OWASP LLM prompt firewall |
| `11` | `supplysecure` | **SupplySecure** | Software Supply Chain Security | CI/CD pipeline attack graph, SLSA provenance & Cosign verifier |
| `12` | `policysecure` | **PolicySecure** | Policy-as-Code & RQL Studio | Unified RQL parser/compiler (`config`, `event`, `network`, `iam`, `data`, `ai`) |
| `13` | `compliancesecure` | **ComplianceSecure** | Executive Compliance Command | Cross-framework crosswalk (CIS, NIST, SOC 2, PCI-DSS, HIPAA, ISO 27001) |

---

## Architectural Principles

1. **100% Pure Rust**: Zero Electron, zero Tauri, and zero OS webview wrappers. Native desktop binaries run with `< 15 MB` executable size and `< 80 MB` idle RAM.
2. **Deterministic 4-Way Control ("Built for Agents")**: Every user action is a serializable `Command` struct. The engine can be driven via interactive GUI, high-speed CLI, JSON-RPC, or as a native **Model Context Protocol (MCP)** server with offscreen screenshot rendering.
3. **Unified Resource Query Language (`cloudsecure-rql`)**: A zero-copy parser (`winnow`) supporting all 6 RQL query families across multi-cloud environments.
4. **Security Asset & Exposure Graph (`cloudsecure-graph`)**: High-performance directed graph representation (`petgraph`) saved to local SQLite (WAL) or portable `.csec` snapshots.
5. **Local-First & Read-Only Assessment**: Cloud connectors operate in read-only mode by default. Remediation playbooks emit reviewable Terraform and CLI diff patches requiring human approval before execution.

---

## Repository Documentation & Implementation Plans

- [DESIGN.md](DESIGN.md): Visual design contract, technical HUD grid system, typography, and WCAG AA verified color tokens.
- [cloudsecure-master-spec.md](project-specs/cloudsecure-master-spec.md): Architectural blueprint, threat model, and 10-point Red-Team risk register.
- [cloudsecure-apps-catalog-spec.md](project-specs/cloudsecure-apps-catalog-spec.md): Deep-dive specifications for all 14 applications (data structures, UI layouts, CLI arguments, and MCP tools).
- [cloudsecure-website-and-github-spec.md](project-specs/cloudsecure-website-and-github-spec.md): Portal architecture (`axum` static site generator replicating `getartcraft.com`) and GitHub release pipeline.
- [cloudsecure-architecture.md](project-docs/cloudsecure-architecture.md): Cargo workspace layout, ADRs, RQL grammar, and Wasm size budgeting.
- [cloudsecure-tasklist.md](project-tasks/cloudsecure-tasklist.md): 42-task sequential implementation plan mapped across 21 specialized agency agent personas.

---

## License

This project is licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
