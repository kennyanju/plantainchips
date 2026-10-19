# CloudSecure Master Execution Task List (For Gemini 3.8 Flash)

> **Authored by**: `agency-agents-orchestrator` & `agency-senior-project-manager`  
> **Target Executor**: Gemini 3.8 Flash  
> **Specification References**:
> - `DESIGN.md` (Visual Identity, WCAG AA Tokens, Antislop Rules)
> - `project-specs/cloudsecure-master-spec.md` (Master Architecture & Red-Teaming)
> - `project-specs/cloudsecure-apps-catalog-spec.md` (14 Rust App Specifications)
> - `project-specs/cloudsecure-website-and-github-spec.md` (Web Portal & GitHub Automation)
> - `project-docs/cloudsecure-architecture.md` (ADRs, CSS Foundation, `egui` Theme, RQL EBNF)

---

## 1. Orchestration Protocol for Gemini 3.8 Flash

When Gemini 3.8 Flash executes this plan, it MUST operate as **`agency-agents-orchestrator`** following this exact loop for every task from **Task 01** to **Task 42**:

1. **Load Agent Persona**: Read the assigned Agency skill file (`SKILL.md`) listed in the task's `Assigned Agent` field.
2. **Execute Implementation**: Create or modify ONLY the files listed in `Files to Create/Edit`, adhering strictly to `DESIGN.md` and `[workspace.lints.rust] unsafe_code = "forbid"`.
3. **Run Task Verification Commands**: Run the exact `Verification` commands specified in the task (`cargo check`, `cargo test`, `cargo clippy -- -D warnings`, `contrast-check.py`, or Playwright).
4. **Run Mandatory QA Loop (`EvidenceQA` + `UI Finish-Gate Reviewer` + `antislop`)**:
   - Verify zero em dashes (`grep -rn $'\xe2\x80\x94' crates/ apps/ web/ docs/ README.md` must return 0 matches).
   - Verify Empty, Loading, and Error states exist on all data views (R-27).
   - Capture offscreen PNG (`cargo xtask render-screenshots`) or Playwright screenshot (`./qa-playwright-capture.sh`).
   - Only mark `[x]` in `project-tasks/cloudsecure-tasklist.md` when both code tests and visual/antislop gates PASS. Maximum 3 retry attempts per task before escalating.

---

## 2. Specialist Agency Agent Roster (21 Agents Mapped)

| # | Agent Name | Skill File Path | Assigned Tasks |
|---|---|---|---|
| 1 | `agency-agents-orchestrator` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-agents-orchestrator/SKILL.md` | Pipeline Controller (All Waves) |
| 2 | `agency-master-plan-architect` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-master-plan-architect/SKILL.md` | Architectural Guardrail Verification |
| 3 | `agency-senior-project-manager` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-senior-project-manager/SKILL.md` | Task Tracking & Scope Audit |
| 4 | `agency-software-architect` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-software-architect/SKILL.md` | Tasks 01, 02, 03 |
| 5 | `agency-cloud-security-architect` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md` | Tasks 04, 05, 11, 14, 18, 19 |
| 6 | `agency-application-security-engineer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md` | Tasks 06, 12, 13, 15, 16, 20, 21 |
| 7 | `agency-threat-detection-engineer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-threat-detection-engineer/SKILL.md` | Task 17 |
| 8 | `agency-compliance-auditor` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-compliance-auditor/SKILL.md` | Tasks 22, 23 |
| 9 | `agency-ux-architect` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-ux-architect/SKILL.md` | Tasks 07, 29 |
| 10 | `agency-ui-designer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-ui-designer/SKILL.md` | Tasks 08, 30 |
| 11 | `agency-mcp-builder` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-mcp-builder/SKILL.md` | Task 09 |
| 12 | `agency-desktop-app-engineer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-desktop-app-engineer/SKILL.md` | Tasks 10, 24, 25 |
| 13 | `agency-webassembly-engineer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-webassembly-engineer/SKILL.md` | Tasks 26, 27 |
| 14 | `agency-rust-refactoring-specialist` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-rust-refactoring-specialist/SKILL.md` | Task 28 |
| 15 | `agency-backend-architect` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-backend-architect/SKILL.md` | Tasks 31, 35 |
| 16 | `agency-frontend-developer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-frontend-developer/SKILL.md` | Tasks 32, 33, 34 |
| 17 | `agency-brand-guardian` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-brand-guardian/SKILL.md` | Task 36 |
| 18 | `agency-technical-writer` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-technical-writer/SKILL.md` | Task 37 |
| 19 | `agency-git-workflow-master` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-git-workflow-master/SKILL.md` | Task 38 |
| 20 | `agency-devops-automator` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-devops-automator/SKILL.md` | Tasks 39, 40 |
| 21 | `agency-evidence-collector` + `agency-ui-finish-gate-reviewer` + `agency-reality-checker` | `/Users/sadiqadeyanju/.gemini/config/skills/agency-reality-checker/SKILL.md` | Per-Task QA Gate + Tasks 41, 42 |

---

## Wave 1: Workspace Foundation & Shared Rust Core (`crates/*`)

### [ ] Task 01: Cargo Workspace Root, Toolchain & `xtask` Skeleton
- **Assigned Agent**: `agency-software-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-software-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Software Architect. Initialize the root Cargo workspace for CloudSecure matching storytold/craft-launcher and storytold/photocraft conventions: resolver = '3', edition = '2024', license = 'MIT OR Apache-2.0', and [workspace.lints.rust] unsafe_code = 'forbid'. Create rust-toolchain.toml, LICENSE-MIT, LICENSE-APACHE, .gitignore, and the xtask crate skeleton with clap subcommands (verify, build-wasm, render-screenshots, package, github-init)."`
- **Files to Create/Edit**:
  - `[NEW]` `Cargo.toml`
  - `[NEW]` `rust-toolchain.toml`
  - `[NEW]` `.gitignore`
  - `[NEW]` `LICENSE-MIT`
  - `[NEW]` `LICENSE-APACHE`
  - `[NEW]` `xtask/Cargo.toml`
  - `[NEW]` `xtask/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo check -p xtask` exits 0.
  - `cargo run -p xtask -- --help` prints all 5 subcommands (`verify`, `build-wasm`, `render-screenshots`, `package`, `github-init`).

### [ ] Task 02: Canonical Domain Types & Mandatory Secret Redactor (`crates/cloudsecure-types`)
- **Assigned Agent**: `agency-software-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-software-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Software Architect. Implement crates/cloudsecure-types containing all shared domain structs and enums: CloudProvider (Aws, Azure, Gcp, Oci, Kubernetes, Local), CnapPillar (Cspm, Dspm, Cwpp, Ciem, Aspm, Waas, Cdr, Graph, Cns, AiSpm, SupplyChain, Policy, Pulse), AppSlug (all 13 apps + Launcher), AppCatalogEntry, AssetId, ResourceRecord, Severity (Critical, High, Medium, Low, Pass with geometric glyph and WCAG hex helpers), ComplianceFramework (CisAws3, CisAzure2, CisGcp2, Nist80053, Soc2, PciDss4, Hipaa, Gdpr, Iso27001, OwaspTop10, Slsa1), Finding, RemediationPatch, SarifReport (SARIF 2.1.0), and RedactedSecret (which masks raw strings, computes a SHA-256 fingerprint, and zeroizes raw buffers on drop)."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-types/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-types/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-types/src/catalog.rs` (defines canonical metadata, `--app-ink` hexes, and descriptions for all 13 apps + Launcher)
  - `[NEW]` `crates/cloudsecure-types/src/redaction.rs`
  - `[NEW]` `crates/cloudsecure-types/src/sarif.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-types` passes unit tests verifying all 13 `AppCatalogEntry` records, SARIF 2.1.0 JSON serialization, and `RedactedSecret` never leaking raw secret substrings in `Debug`, `Display`, or `serde_json::to_string`.

### [ ] Task 03: Cloud Security Graph & Shortest Attack-Path Engine (`crates/cloudsecure-graph`)
- **Assigned Agent**: `agency-software-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-software-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Software Architect. Implement crates/cloudsecure-graph using petgraph::stable_graph::StableDiGraph<AssetNode, RelationEdge>. Implement blast-radius BFS traversal, weighted Dijkstra shortest breach path from Internet/Untrusted entry nodes to CrownJewel nodes, betweenness-centrality choke-point ranking, 'what-if' edge suppression simulation, and deterministic zstd/JSON .csec snapshot load/save."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-graph/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-graph/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-graph/src/attack_path.rs`
  - `[NEW]` `crates/cloudsecure-graph/src/snapshot.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-graph` passes tests finding multi-hop toxic combinations (`Internet -> PublicPod -> IAMRole -> CrownJewelS3`) and computing the single choke-point edge whose removal severs all paths.

### [ ] Task 04: Unified Resource Query Language Engine (`crates/cloudsecure-rql`)
- **Assigned Agent**: `agency-cloud-security-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Cloud Security Architect. Implement crates/cloudsecure-rql matching the EBNF grammar in project-docs/cloudsecure-architecture.md. Support all 5 RQL families (config from cloud.resource, network from vpc.flow_record, event from cloud.audit_logs, iam from cloud.entitlements, data from cloud.data_store), boolean logic (and, or, not, parentheses), comparators (=, !=, >, >=, <, <=, in, not in, contains, starts with, is true, is false, is empty, is not empty), nested JSON path evaluation, AST explain-plan output, syntax autocomplete suggestions, and proptest fuzz tests."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-rql/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-rql/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-rql/src/ast.rs`
  - `[NEW]` `crates/cloudsecure-rql/src/parser.rs`
  - `[NEW]` `crates/cloudsecure-rql/src/eval.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-rql` passes 30+ query tests across all 5 RQL families and `proptest` fuzzing (1,000 random inputs with 0 panics).

### [ ] Task 05: Built-in 150-Rule CNAPP Policy Library (`crates/cloudsecure-policy`)
- **Assigned Agent**: `agency-cloud-security-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Cloud Security Architect. Implement crates/cloudsecure-policy containing 150+ real, production-grade security policies across all 13 CNAPP domains (CSPM CIS AWS/Azure/GCP rules, DSPM exposure rules, CWPP container/runtime rules, CIEM privilege escalation rules, IaC security rules (IAC_*), WAAS OWASP rules, CDR CloudTrail threat rules, CNS network rules, AI-SPM model rules, Supply Chain CI workflow rules), each mapped to compliance frameworks and deterministic remediation templates."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-policy/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-policy/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-policy/src/builtins.rs`
  - `[NEW]` `crates/cloudsecure-policy/src/remediation.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-policy` verifies at least 150 distinct policies exist, every policy has a valid RQL or AST matcher, compliance mapping, and remediation generator, and every policy passes positive/negative unit fixtures.

### [ ] Task 06: Multi-Cloud Connectors & Benchmark Corpus (`crates/cloudsecure-connectors` & `crates/cloudsecure-testkit`)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement crates/cloudsecure-connectors and crates/cloudsecure-testkit. Provide parsers for AWS/Azure/GCP JSON snapshots, Terraform HCL (.tf), Kubernetes YAML, Dockerfiles, GitHub Actions YAML, Lockfiles (Cargo.lock, package-lock.json), OpenAPI YAML, CloudTrail JSONL, and VPC Flow Logs. Include a deterministic multi-cloud benchmark corpus generator (420 realistic cloud resources, 50 IaC files, 120 audit events, 15 data stores with synthetic Luhn-valid test cards and fake keys) so every app works out-of-the-box offline."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-connectors/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-connectors/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-connectors/src/corpus.rs`
  - `[NEW]` `crates/cloudsecure-testkit/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-testkit/src/lib.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-connectors -p cloudsecure-testkit` passes, confirming the synthetic multi-cloud corpus loads in `< 20 ms` and triggers findings across all 13 CNAPP domains.

### [ ] Task 07: Shared `egui` Studio UI Framework & Theme System (`crates/cloudsecure-ui` Part 1)
- **Assigned Agent**: `agency-ux-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-ux-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as ArchitectUX. Implement crates/cloudsecure-ui with SecurePalette (Light #F2F1EE and Dark #0B0B0C matching DESIGN.md), deflated font loader (egui_fonts.rs), 10-locale i18n catalog (en, pt-BR, cs, fr, de, hu, ja, pl, ru, zh-CN, es), HudTopBar, CommandPalette (Cmd+K / Ctrl+K), and DataViewContainer<T> which enforces Empty, Loading, and Error states at the Rust type level (R-27)."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-ui/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-ui/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/theme.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/egui_fonts.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/i18n.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/state_view.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-ui` verifies Light/Dark color contrast ratios >= 4.5:1, all 10 locales resolve keys with English fallback, and `DataViewContainer` renders Empty, Loading, Error, and Loaded states cleanly in headless `egui` test runs.

### [ ] Task 08: Geometric App Icons, Virtualized Tables, Diff Viewer & Graph Canvas (`crates/cloudsecure-ui` Part 2)
- **Assigned Agent**: `agency-ui-designer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-ui-designer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as UI Designer. Add vector/painter rendering in crates/cloudsecure-ui for all 13 bespoke geometric app marks + 5 non-color severity shape glyphs (Octagon, Triangle, Diamond, Circle, CheckSquare), VirtualizedFindingTable (keyboard navigable Up/Down/Enter), SecurityGraphViewport (2D interactive force/layered DAG with pan, zoom, node selection, and edge toggle), and RemediationDiffView (unified and side-by-side HCL/YAML/JSON diff)."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-ui/src/icons.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/table.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/graph_view.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/diff_view.rs`
  - `[NEW]` `crates/cloudsecure-ui/src/workbench.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-ui` renders every widget in a headless `egui::Context` across Light and Dark modes without panics or layout overflow.

### [ ] Task 09: 4-Way Command Bus, CLI Runner, JSON-RPC & MCP Server (`crates/cloudsecure-automation`)
- **Assigned Agent**: `agency-mcp-builder` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-mcp-builder/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as MCP Builder. Implement crates/cloudsecure-automation defining the CloudSecureAppEngine trait, Undo/Redo command ledger, standard CLI runner (--rql, --input, --format {table,json,sarif,csv,csec}, --mcp, --json-rpc), JSON-RPC 2.0 stdio dispatcher, and full Model Context Protocol (MCP) server supporting initialize, tools/list, tools/call, and resources/list."`
- **Files to Create/Edit**:
  - `[NEW]` `crates/cloudsecure-automation/Cargo.toml`
  - `[NEW]` `crates/cloudsecure-automation/src/lib.rs`
  - `[NEW]` `crates/cloudsecure-automation/src/mcp.rs`
  - `[NEW]` `crates/cloudsecure-automation/src/cli.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-automation` sends simulated MCP `initialize`, `tools/list`, and `tools/call` JSON-RPC messages and verifies spec-compliant responses.

---

## Wave 2: `LauncherSecure` (`apps/launchersecure`)

### [ ] Task 10: `LauncherSecure` Native + Wasm App (`apps/launchersecure`)
- **Assigned Agent**: `agency-desktop-app-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-desktop-app-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Desktop App Engineer. Implement apps/launchersecure replicating storytold/craft-launcher for the 13 CloudSecure security apps. Include: (1) Card Grid View and Sortable Table View toggle, (2) CNAPP pillar filter & instant search, (3) OS/CPU package detector (DMG, MSI, .deb, .rpm, AppImage, Flatpak, FreeBSD, Wasm), (4) Ed25519 + SHA-256 release manifest verifier and N-1 rollback manager, (5) 10-locale selector & Light/Dark/System theme toggle, (6) rotating logs (launchersecure.log, .1.log, .2.log), and (7) Trunk index.html for Wasm."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/launchersecure/Cargo.toml`
  - `[NEW]` `apps/launchersecure/index.html`
  - `[NEW]` `apps/launchersecure/src/lib.rs`
  - `[NEW]` `apps/launchersecure/src/main.rs`
  - `[NEW]` `apps/launchersecure/src/updater.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p launchersecure` passes tests for Grid/Table view switching, SHA-256 mismatch quarantine, Ed25519 signature verification, and N-1 rollback.

---

## Wave 3: Core CNAPP Posture, Data, Workload & Identity Apps (Apps 01 to 04)

### [ ] Task 11: App 01 - `PostureSecure` (CSPM Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-cloud-security-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Cloud Security Architect. Implement apps/posturesecure and apps/posturesecure-cli according to App 01 in project-specs/cloudsecure-apps-catalog-spec.md. Include multi-cloud resource inventory, 8-framework compliance posture matrix, drift detection against baseline state, Terraform/CLI remediation diff generator, full egui workbench (Light/Dark, Empty/Loading/Error states), CLI binary, and MCP tools (posture_run_rql, posture_evaluate_compliance, posture_detect_drift, posture_generate_remediation)."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/posturesecure/Cargo.toml`
  - `[NEW]` `apps/posturesecure/index.html`
  - `[NEW]` `apps/posturesecure/src/lib.rs`
  - `[NEW]` `apps/posturesecure/src/main.rs`
  - `[NEW]` `apps/posturesecure-cli/Cargo.toml`
  - `[NEW]` `apps/posturesecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p posturesecure -p posturesecure-cli` and `cargo run -p posturesecure-cli -- scan --corpus bundled --format sarif` pass with 0 warnings.

### [ ] Task 12: App 02 - `DataSecure` (DSPM Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement apps/datasecure and apps/datasecure-cli according to App 02 in project-specs/cloudsecure-apps-catalog-spec.md. Include linear-time PII/PCI/PHI/Secret/IP classification (with Luhn & SSN validation), mandatory RedactedSecret masking, shadow data lineage graph, DDR exfiltration detector, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/datasecure/Cargo.toml`
  - `[NEW]` `apps/datasecure/index.html`
  - `[NEW]` `apps/datasecure/src/lib.rs`
  - `[NEW]` `apps/datasecure/src/main.rs`
  - `[NEW]` `apps/datasecure-cli/Cargo.toml`
  - `[NEW]` `apps/datasecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p datasecure -p datasecure-cli` verifies Luhn PCI detection, shadow data lineage tracking, and 100% redaction of sensitive samples.

### [ ] Task 13: App 03 - `WorkloadSecure` (CWPP Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement apps/workloadsecure and apps/workloadsecure-cli according to App 03 in project-specs/cloudsecure-apps-catalog-spec.md. Include OCI/Docker layer-by-layer package & CVE X-ray, deleted-layer secret detector, runtime behavioral profiler (processes, capabilities, syscalls), Kubernetes SecurityContext/Seccomp generator, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/workloadsecure/Cargo.toml`
  - `[NEW]` `apps/workloadsecure/index.html`
  - `[NEW]` `apps/workloadsecure/src/lib.rs`
  - `[NEW]` `apps/workloadsecure/src/main.rs`
  - `[NEW]` `apps/workloadsecure-cli/Cargo.toml`
  - `[NEW]` `apps/workloadsecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p workloadsecure -p workloadsecure-cli` passes layer CVE attribution and runtime anomaly detection tests.

### [ ] Task 14: App 04 - `IdentitySecure` (CIEM Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-cloud-security-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Cloud Security Architect. Implement apps/identitysecure and apps/identitysecure-cli according to App 04 in project-specs/cloudsecure-apps-catalog-spec.md. Include AWS/Azure/GCP/K8s Net-Effective Permission solver (Identity Policies + Resource Policies + SCPs + Permission Boundaries), 21-vector IAM privilege escalation detector, Granted-vs-Used right-sizer synthesizing least-privilege IAM JSON/Terraform diffs, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/identitysecure/Cargo.toml`
  - `[NEW]` `apps/identitysecure/index.html`
  - `[NEW]` `apps/identitysecure/src/lib.rs`
  - `[NEW]` `apps/identitysecure/src/main.rs`
  - `[NEW]` `apps/identitysecure-cli/Cargo.toml`
  - `[NEW]` `apps/identitysecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p identitysecure -p identitysecure-cli` verifies SCP deny overrides, `iam:PassRole` escalation detection, and least-privilege policy synthesis.

---

## Wave 4: Shift-Left, API, CDR, Graph & Network Apps (Apps 05 to 09)

### [ ] Task 15: App 05 - `CodeSecure` (ASPM & IaC Policy Engine Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement apps/codesecure and apps/codesecure-cli according to App 05 in project-specs/cloudsecure-apps-catalog-spec.md. Include Multi-cloud IAC_* IaC scanner (Terraform, K8s, Dockerfile, CloudFormation, GitHub Actions), SCA lockfile vulnerability scanner, CycloneDX 1.5 & SPDX 2.3 SBOM generator, one-click IaC auto-fix patch generator, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/codesecure/Cargo.toml`
  - `[NEW]` `apps/codesecure/index.html`
  - `[NEW]` `apps/codesecure/src/lib.rs`
  - `[NEW]` `apps/codesecure/src/main.rs`
  - `[NEW]` `apps/codesecure-cli/Cargo.toml`
  - `[NEW]` `apps/codesecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p codesecure -p codesecure-cli` verifies HCL/K8s/Dockerfile `CKV_*` rules, valid CycloneDX JSON export, and auto-fix HCL generation.

### [ ] Task 16: App 06 - `WaasSecure` (WAAS API & Layer-7 Firewall Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement apps/waassecure and apps/waassecure-cli according to App 06 in project-specs/cloudsecure-apps-catalog-spec.md. Include OpenAPI 3.x vs HTTP traffic shadow/zombie API discovery, OWASP Top 10 & API Security Top 10 payload inspector (SQLi, XSS, SSRF metadata 169.254.169.254, BOLA, JWT alg:none), Envoy/ModSecurity/AWS WAFv2 virtual patch generator, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/waassecure/Cargo.toml`
  - `[NEW]` `apps/waassecure/index.html`
  - `[NEW]` `apps/waassecure/src/lib.rs`
  - `[NEW]` `apps/waassecure/src/main.rs`
  - `[NEW]` `apps/waassecure-cli/Cargo.toml`
  - `[NEW]` `apps/waassecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p waassecure -p waassecure-cli` passes shadow API discovery, SSRF/SQLi detection, and WAF rule synthesis tests.

### [ ] Task 17: App 07 - `ThreatSecure` (CDR & MITRE ATT&CK Cloud Workbench Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-threat-detection-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-threat-detection-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Threat Detection Engineer. Implement apps/threatsecure and apps/threatsecure-cli according to App 07 in project-specs/cloudsecure-apps-catalog-spec.md. Include CloudTrail, VPC Flow Log, and K8s Audit Log stream correlation, multi-stage kill-chain incident storyline builder, interactive MITRE ATT&CK for Cloud matrix, forensic containment playbook generator, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/threatsecure/Cargo.toml`
  - `[NEW]` `apps/threatsecure/index.html`
  - `[NEW]` `apps/threatsecure/src/lib.rs`
  - `[NEW]` `apps/threatsecure/src/main.rs`
  - `[NEW]` `apps/threatsecure-cli/Cargo.toml`
  - `[NEW]` `apps/threatsecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p threatsecure -p threatsecure-cli` correlates multi-step CloudTrail attack sequences and maps them to MITRE ATT&CK tactics.

### [ ] Task 18: App 08 - `GraphSecure` (Attack Path & Exposure Graph Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-cloud-security-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Cloud Security Architect. Implement apps/graphsecure and apps/graphsecure-cli according to App 08 in project-specs/cloudsecure-apps-catalog-spec.md. Wire cloudsecure-graph into an interactive wgpu/egui force-directed and layered DAG workbench with toxic-combination templates, betweenness-centrality choke-point optimization, interactive 'What-If' edge remediation simulation, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/graphsecure/Cargo.toml`
  - `[NEW]` `apps/graphsecure/index.html`
  - `[NEW]` `apps/graphsecure/src/lib.rs`
  - `[NEW]` `apps/graphsecure/src/main.rs`
  - `[NEW]` `apps/graphsecure-cli/Cargo.toml`
  - `[NEW]` `apps/graphsecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p graphsecure -p graphsecure-cli` verifies shortest breach path discovery and interactive choke-point removal.

### [ ] Task 19: App 09 - `NetSecure` (CNS & Zero-Trust Microsegmentation Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-cloud-security-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-cloud-security-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Cloud Security Architect. Implement apps/netsecure and apps/netsecure-cli according to App 09 in project-specs/cloudsecure-apps-catalog-spec.md. Include symbolic CIDR/port reachability analysis across VPC Route Tables, IGW/NAT/TGW, Security Groups, NACLs, and K8s NetworkPolicies, plus flow-log-driven Zero-Trust K8s NetworkPolicy & Security Group synthesizer, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/netsecure/Cargo.toml`
  - `[NEW]` `apps/netsecure/index.html`
  - `[NEW]` `apps/netsecure/src/lib.rs`
  - `[NEW]` `apps/netsecure/src/main.rs`
  - `[NEW]` `apps/netsecure-cli/Cargo.toml`
  - `[NEW]` `apps/netsecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p netsecure -p netsecure-cli` verifies symbolic reachability proofs and generates valid default-deny + explicit-allow K8s `NetworkPolicy` manifests (matching both ingress and egress rules).

---

## Wave 5: AI-SPM, Supply Chain, Policy IDE & Executive Command Apps (Apps 10 to 13)

### [ ] Task 20: App 10 - `AiSecure` (AI-SPM Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement apps/aisecure and apps/aisecure-cli according to App 10 in project-specs/cloudsecure-apps-catalog-spec.md. Include AI/ML BOM inventory (Bedrock, Vertex, Azure OpenAI, local models), Python pickle opcode arbitrary-code-execution scanner vs safetensors verifier, DSPM-to-RAG vector store sensitive data lineage auditor, OWASP LLM Top 10 posture evaluator, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/aisecure/Cargo.toml`
  - `[NEW]` `apps/aisecure/index.html`
  - `[NEW]` `apps/aisecure/src/lib.rs`
  - `[NEW]` `apps/aisecure/src/main.rs`
  - `[NEW]` `apps/aisecure-cli/Cargo.toml`
  - `[NEW]` `apps/aisecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p aisecure -p aisecure-cli` detects malicious pickle opcodes (`REDUCE`/`GLOBAL`), validates `safetensors` headers, and flags PII-tainted RAG indexes.

### [ ] Task 21: App 11 - `SupplySecure` (Software Supply Chain & SLSA Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-application-security-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-application-security-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Application Security Engineer. Implement apps/supplysecure and apps/supplysecure-cli according to App 11 in project-specs/cloudsecure-apps-catalog-spec.md. Include GitHub Actions / GitLab CI pipeline vulnerability scanner (unpinned actions, pull_request_target injection, excessive GITHUB_TOKEN permissions), automatic 40-char SHA action pinner, SLSA v1.0 in-toto provenance verifier, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/supplysecure/Cargo.toml`
  - `[NEW]` `apps/supplysecure/index.html`
  - `[NEW]` `apps/supplysecure/src/lib.rs`
  - `[NEW]` `apps/supplysecure/src/main.rs`
  - `[NEW]` `apps/supplysecure-cli/Cargo.toml`
  - `[NEW]` `apps/supplysecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p supplysecure -p supplysecure-cli` flags unpinned actions and `pull_request_target` flaws and verifies SLSA provenance predicates.

### [ ] Task 22: App 12 - `PolicySecure` (Unified RQL & Policy-as-Code Studio Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-compliance-auditor` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-compliance-auditor/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Compliance Auditor. Implement apps/policysecure and apps/policysecure-cli according to App 12 in project-specs/cloudsecure-apps-catalog-spec.md. Build the interactive RQL & YAML Policy-as-Code IDE with live AST visualization, query execution profiler, positive/negative fixture unit test runner, custom policy pack bundler, egui workbench, CLI, and MCP server."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/policysecure/Cargo.toml`
  - `[NEW]` `apps/policysecure/index.html`
  - `[NEW]` `apps/policysecure/src/lib.rs`
  - `[NEW]` `apps/policysecure/src/main.rs`
  - `[NEW]` `apps/policysecure-cli/Cargo.toml`
  - `[NEW]` `apps/policysecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p policysecure -p policysecure-cli` runs policy pack unit tests and AST explain plans in `< 5 ms`.

### [ ] Task 23: App 13 - `ComplianceSecure` (Executive Command & Compliance Audit Exporter Desktop, Wasm, CLI & MCP)
- **Assigned Agent**: `agency-compliance-auditor` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-compliance-auditor/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Compliance Auditor. Implement apps/compliancesecure and apps/compliancesecure-cli according to App 13 in project-specs/cloudsecure-apps-catalog-spec.md. Aggregate findings across all 12 CloudSecure modules into the Prioritized Top-10 Breach-Stopping Remediation Queue (no generic 4-card filler dashboard per DESIGN.md) and compile signed Audit Evidence Bundles for SOC 2, ISO 27001, PCI-DSS v4, HIPAA, and NIST CSF 2.0 in HTML, Markdown, CSV, JSON, and SARIF."`
- **Files to Create/Edit**:
  - `[NEW]` `apps/compliancesecure/Cargo.toml`
  - `[NEW]` `apps/compliancesecure/index.html`
  - `[NEW]` `apps/compliancesecure/src/lib.rs`
  - `[NEW]` `apps/compliancesecure/src/main.rs`
  - `[NEW]` `apps/compliancesecure-cli/Cargo.toml`
  - `[NEW]` `apps/compliancesecure-cli/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p compliancesecure -p compliancesecure-cli` aggregates multi-app findings and generates a complete SOC 2 / PCI-DSS v4 audit bundle with SHA-256 evidence manifest.

---

## Wave 6: Packaging, Offscreen Visual Verification, Wasm & Workspace Hardening

### [ ] Task 24: Offscreen Screenshot Renderer (`cargo xtask render-screenshots`)
- **Assigned Agent**: `agency-desktop-app-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-desktop-app-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Desktop App Engineer. Implement cargo xtask render-screenshots in xtask/src/screenshots.rs to drive launchersecure and all 13 CloudSecure apps offscreen in both Light (#F2F1EE) and Dark (#0B0B0C) themes against the bundled multi-cloud corpus, rendering deterministic high-resolution PNG/SVG workbench previews into docs/screenshots/ and web/cloudsecure-site/static/images/apps/."`
- **Files to Create/Edit**:
  - `[NEW]` `xtask/src/screenshots.rs`
  - `[MODIFY]` `xtask/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo run -p xtask -- render-screenshots` generates 28 deterministic workbench previews (14 apps x Light/Dark) with zero errors.

### [ ] Task 25: Release Packager & Ed25519 Manifest Signer (`cargo xtask package`)
- **Assigned Agent**: `agency-desktop-app-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-desktop-app-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Desktop App Engineer. Implement cargo xtask package in xtask/src/package.rs to build release binaries, package platform archives (.dmg layout, .msi/.zip layout, .deb/.rpm/.AppImage layout, FreeBSD archive), compute SHA-256 checksums, and emit an Ed25519-signed manifest.json consumed by launchersecure."`
- **Files to Create/Edit**:
  - `[NEW]` `xtask/src/package.rs`
  - `[MODIFY]` `xtask/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p xtask` verifies archive generation, SHA-256 digest calculation, and Ed25519 signature verification by `launchersecure`.

### [ ] Task 26: WebAssembly Build Pipeline & Size Gate (`cargo xtask build-wasm`)
- **Assigned Agent**: `agency-webassembly-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-webassembly-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as WebAssembly Engineer. Implement cargo xtask build-wasm in xtask/src/wasm.rs to compile the apps for wasm32-unknown-unknown (with release profile opt-level='z', lto=true, codegen-units=1, strip=true), generate interactive browser shells under web/cloudsecure-site/static/wasm/<app-slug>/, and enforce the < 900 KB gzipped size budget."`
- **Files to Create/Edit**:
  - `[NEW]` `xtask/src/wasm.rs`
  - `[MODIFY]` `Cargo.toml` (release profile optimization)
  - `[MODIFY]` `xtask/src/main.rs`
- **Acceptance Criteria & Verification**:
  - `cargo check --workspace --target wasm32-unknown-unknown` (for all Wasm-compatible crates/apps) succeeds with 0 errors.

### [ ] Task 27: Interactive Browser WebAssembly Workbench Loader
- **Assigned Agent**: `agency-webassembly-engineer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-webassembly-engineer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as WebAssembly Engineer. Create the streaming WebAssembly loader and offline browser workbench host in web/cloudsecure-site/static/js/wasm-host.js so clicking 'Launch in Browser (Wasm)' on any of the 13 apps opens a responsive, keyboard-accessible interactive workbench pre-loaded with the bundled multi-cloud security corpus."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/static/js/wasm-host.js`
- **Acceptance Criteria & Verification**:
  - Verified in Playwright headless browser test with zero console errors.

### [ ] Task 28: Workspace-Wide Rust Refactoring, Clippy & Zero-Panic Hardening
- **Assigned Agent**: `agency-rust-refactoring-specialist` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-rust-refactoring-specialist/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Rust Refactoring Specialist. Audit all crates/* and apps/* for ownership efficiency, panic hardening (no unwrap() on untrusted input), zero Clippy warnings (--all-targets -- -D warnings), and antislop-code comment hygiene (remove any decorative separator banners, workflow narration comments, or signature echoes)."`
- **Files to Create/Edit**:
  - `[MODIFY]` Workspace crates as needed for zero Clippy warnings and comment hygiene.
- **Acceptance Criteria & Verification**:
  - `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` exit 0.

---

## Wave 7: `cloudsecure-site` (`getartcraft.com` Replica in Rust), Docs & CI/CD

### [ ] Task 29: CSS Design System & Theme Manager (`web/cloudsecure-site/static/css` & `js`)
- **Assigned Agent**: `agency-ux-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-ux-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as ArchitectUX. Implement web/cloudsecure-site/static/css/design-system.css, layout.css, components.css, and static/js/theme-manager.js following DESIGN.md and project-docs/cloudsecure-architecture.md. Replicate getartcraft.com's exact structural HUD grid (1px --line borders, sticky h-12 top nav, sticky top-12 numbered section eyebrows 01 / ..., 5px corner crosshair ticks, square-cornered bg-invert-bg text-invert-fg buttons, 4-state responsive reflow, and localStorage('cloudsecure-theme') Light/Dark/System toggle)."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/static/css/design-system.css`
  - `[NEW]` `web/cloudsecure-site/static/css/layout.css`
  - `[NEW]` `web/cloudsecure-site/static/css/components.css`
  - `[NEW]` `web/cloudsecure-site/static/js/theme-manager.js`
- **Acceptance Criteria & Verification**:
  - Run `contrast-check.py` on all color pairs in `design-system.css`; all pairs pass WCAG AA (`>= 4.5:1` text, `>= 3.0:1` boundaries).

### [ ] Task 30: Bespoke SVG Brand Logo & 13 App Icon Assets (`web/cloudsecure-site/static/images/`)
- **Assigned Agent**: `agency-ui-designer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-ui-designer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as UI Designer. Generate clean, theme-aware geometric SVG icons for cloudsecure-icon.svg and all 13 apps (posturesecure, datasecure, workloadsecure, identitysecure, codesecure, waassecure, threatsecure, graphsecure, netsecure, aisecure, supplysecure, policysecure, compliancesecure) in web/cloudsecure-site/static/images/apps/<slug>/icon.svg matching the geometric motifs and --app-ink tokens in DESIGN.md."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/static/images/cloudsecure-icon.svg`
  - `[NEW]` `web/cloudsecure-site/static/images/apps/*/icon.svg` (13 SVG files)
- **Acceptance Criteria & Verification**:
  - Every SVG is valid XML, uses semantic `currentColor` / `--app-ink` strokes, and renders crisply in both Light and Dark modes.

### [ ] Task 31: `cloudsecure-site` Rust `axum` Server, Static Builder & Live RQL API
- **Assigned Agent**: `agency-backend-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-backend-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Backend Architect. Create web/cloudsecure-site/Cargo.toml and src/main.rs using axum. Implement live HTTP serving (serve --port 8080), static site generation (build-static --out ./dist-web), and JSON API endpoints (/api/rql/evaluate, /api/catalog, /api/attack-paths, /api/manifest) wired directly to cloudsecure-rql, cloudsecure-graph, cloudsecure-policy, and cloudsecure-connectors."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/Cargo.toml`
  - `[NEW]` `web/cloudsecure-site/src/main.rs`
  - `[NEW]` `web/cloudsecure-site/src/api.rs`
  - `[NEW]` `web/cloudsecure-site/src/ssg.rs`
- **Acceptance Criteria & Verification**:
  - `cargo test -p cloudsecure-site` tests `/api/rql/evaluate` and `/api/attack-paths` with valid and invalid RQL queries.

### [ ] Task 32: Web Portal Home (`/`) & Interactive `/rql` Playground Pages
- **Assigned Agent**: `agency-frontend-developer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-frontend-developer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Frontend Developer. Implement the Home page (/) and Interactive RQL Playground (/rql) in web/cloudsecure-site/src/pages/home.rs and rql.rs. Replicate getartcraft.com's layout rhythm with sticky numbered HUD eyebrows, live interactive RQL & Attack Path query execution against the 420-resource corpus, Terraform remediation diff viewer, and explicit Empty, Loading, and Syntax Error states (R-27)."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/src/pages/mod.rs`
  - `[NEW]` `web/cloudsecure-site/src/pages/layout.rs`
  - `[NEW]` `web/cloudsecure-site/src/pages/home.rs`
  - `[NEW]` `web/cloudsecure-site/src/pages/rql.rs`
- **Acceptance Criteria & Verification**:
  - Every CTA button and interactive RQL preset works with zero dead links (R-24, R-26) and zero em dashes (R-02).

### [ ] Task 33: Web Portal `/apps` Suite Catalog & 13 `/apps/:slug` Deep-Dive Pages
- **Assigned Agent**: `agency-frontend-developer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-frontend-developer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Frontend Developer. Implement /apps (web/cloudsecure-site/src/pages/apps.rs) replicating getartcraft.com/apps ('Thirteen security apps. One unified architecture.', sticky 01 / CloudSecure Apps eyebrow, Download Launcher CTA, Copy Link button with aria-live feedback, pillar filter, and 13 app showcase bays) AND /apps/:slug (src/pages/app_detail.rs) rendering dedicated deep-dive pages for all 13 CloudSecure apps with interactive Wasm workbench launch, RQL examples, CLI flags, and MCP tool schemas."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/src/pages/apps.rs`
  - `[NEW]` `web/cloudsecure-site/src/pages/app_detail.rs`
- **Acceptance Criteria & Verification**:
  - All 13 `/apps/<slug>` routes return HTTP 200 and render app-specific RQL queries, CLI commands, MCP schemas, and workbench previews.

### [ ] Task 34: Web Portal `/download`, `/docs`, `/security`, `/privacy`, `/terms` Pages
- **Assigned Agent**: `agency-frontend-developer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-frontend-developer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Frontend Developer. Implement /download (OS/CPU installer matrix with SHA-256 copy buttons for macOS DMG, Windows MSI/ZIP, Linux DEB/RPM/AppImage/Flatpak, FreeBSD), /docs (Architecture, RQL EBNF reference, MCP integration guide), and /security, /privacy, /terms in web/cloudsecure-site/src/pages/."`
- **Files to Create/Edit**:
  - `[NEW]` `web/cloudsecure-site/src/pages/download.rs`
  - `[NEW]` `web/cloudsecure-site/src/pages/docs.rs`
  - `[NEW]` `web/cloudsecure-site/src/pages/legal.rs`
- **Acceptance Criteria & Verification**:
  - Every navbar and footer link resolves to a real, complete page (R-24, R-38).

### [ ] Task 35: Static Site Bundle Generation (`dist-web`)
- **Assigned Agent**: `agency-backend-architect` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-backend-architect/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Backend Architect. Wire cargo run -p cloudsecure-site -- build-static --out ./dist-web so it exports all 21 HTML routes (/, /apps, 13 /apps/<slug>, /rql, /download, /docs, /security, /privacy, /terms), static CSS/JS/SVG/PNG assets, and offline corpus JSON for GitHub Pages deployment."`
- **Files to Create/Edit**:
  - `[MODIFY]` `web/cloudsecure-site/src/ssg.rs`
- **Acceptance Criteria & Verification**:
  - `cargo run -p cloudsecure-site -- build-static --out ./dist-web` generates all 21 HTML files and static assets with zero broken internal links.

### [ ] Task 36: Brand Consistency & Antislop Copywriting Audit Across All Surfaces
- **Assigned Agent**: `agency-brand-guardian` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-brand-guardian/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Brand Guardian with antislop-copywriting active. Audit every string in crates/cloudsecure-types/src/catalog.rs, web/cloudsecure-site/src/pages/*, and apps/* to ensure: (1) zero em dashes (R-02), (2) zero banned AI buzzwords (R-16: no 'Seamless', 'Revolutionary', 'Cutting Edge', 'Next Generation', 'AI Powered'), (3) zero fabricated stats or testimonials (R-17, R-18, R-36), and (4) clear non-affiliation disclaimers with enterprise CNAPP Networks."`
- **Files to Create/Edit**:
  - `[MODIFY]` Copy strings across `crates/cloudsecure-types` and `web/cloudsecure-site` if any violation is detected.
- **Acceptance Criteria & Verification**:
  - Automated regex scan for U+2014 (em dash) and R-16 buzzwords returns 0 violations.

### [ ] Task 37: `photocraft`-Grade READMEs & Documentation Suite
- **Assigned Agent**: `agency-technical-writer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-technical-writer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Technical Writer. Write the root README.md (replicating storytold/craft-launcher and storytold/photocraft README structure with badges, architecture table, 13-app directory, installation table across macOS/Windows/Linux/FreeBSD, RQL quickstart, and MCP agent config) plus individual README.md files in apps/launchersecure and all 13 app directories."`
- **Files to Create/Edit**:
  - `[NEW]` `README.md`
  - `[NEW]` `apps/launchersecure/README.md`
  - `[NEW]` `apps/*/README.md` (13 app READMEs)
- **Acceptance Criteria & Verification**:
  - All 15 `README.md` files exist, contain zero em dashes (R-02), and have valid relative links.

### [ ] Task 38: GitHub Repository & Multi-Repo Provisioner (`cargo xtask github-init`)
- **Assigned Agent**: `agency-git-workflow-master` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-git-workflow-master/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as Git Workflow Master. Implement cargo xtask github-init in xtask/src/github.rs to initialize the local Git repository with clean conventional commits, generate scripts/setup-github-org.sh (using gh repo create for either monorepo or 15-repo storytold-style organization layout), and configure branch protection and issue/PR templates in .github/."`
- **Files to Create/Edit**:
  - `[NEW]` `xtask/src/github.rs`
  - `[NEW]` `.github/PULL_REQUEST_TEMPLATE.md`
  - `[NEW]` `.github/ISSUE_TEMPLATE/bug_report.md`
- **Acceptance Criteria & Verification**:
  - `cargo run -p xtask -- github-init --org cloudsecure --dry-run` outputs the complete, valid `gh` provisioning commands for the entire ecosystem.

### [ ] Task 39: GitHub Actions CI, Release & Pages Pipelines (`.github/workflows/`)
- **Assigned Agent**: `agency-devops-automator` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-devops-automator/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as DevOps Automator. Create .github/workflows/ci.yml (fmt, clippy -D warnings, cargo test --workspace, wasm size gate, Playwright visual QA, contrast-check.py gate), .github/workflows/release.yml (matrix build across macOS/Windows/Linux/FreeBSD, codesign/notarytool hooks, SHA-256 + Ed25519 manifest publishing), and .github/workflows/pages.yml (static site + Wasm deployment to GitHub Pages)."`
- **Files to Create/Edit**:
  - `[NEW]` `.github/workflows/ci.yml`
  - `[NEW]` `.github/workflows/release.yml`
  - `[NEW]` `.github/workflows/pages.yml`
- **Acceptance Criteria & Verification**:
  - YAML syntax validation passes on all 3 workflow files; no long-lived cloud secrets used.

### [ ] Task 40: Automated Playwright Visual & Interaction QA Harness (`qa-playwright-capture.sh`)
- **Assigned Agent**: `agency-devops-automator` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-devops-automator/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as DevOps Automator. Create qa-playwright-capture.sh and tests/playwright-qa.spec.mjs required by EvidenceQA and TestingRealityChecker. The script must capture Desktop (1920x1080), Tablet (768x1024), and Mobile (375x667) full-page screenshots in both Light and Dark themes, click through every nav item, theme toggle, mobile menu, pillar filter, copy-link button, and RQL playground execution, assert zero horizontal overflow (scrollWidth <= clientWidth), assert zero console errors, and write public/qa-screenshots/test-results.json."`
- **Files to Create/Edit**:
  - `[NEW]` `qa-playwright-capture.sh`
  - `[NEW]` `tests/playwright-qa.spec.mjs`
- **Acceptance Criteria & Verification**:
  - Script is executable (`chmod +x qa-playwright-capture.sh`) and outputs `public/qa-screenshots/test-results.json`.

### [ ] Task 41: Full-System Visual Evidence Capture & UI Finish-Gate Audit
- **Assigned Agent**: `agency-evidence-collector` + `agency-ui-finish-gate-reviewer` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-ui-finish-gate-reviewer/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as EvidenceQA and UI Finish-Gate Reviewer. Run cargo xtask verify, cargo xtask render-screenshots, and ./qa-playwright-capture.sh http://127.0.0.1:8080 public/qa-screenshots. Inspect every screenshot and test-results.json against DESIGN.md and the antislop Delivery Gate. Record the element-by-element click-through verification report in project-docs/qa-evidence-report.md."`
- **Files to Create/Edit**:
  - `[NEW]` `project-docs/qa-evidence-report.md`
- **Acceptance Criteria & Verification**:
  - `project-docs/qa-evidence-report.md` contains recorded PASS evidence for all 38 `antislop` rules and all UI Finish-Gate criteria.

### [ ] Task 42: Final Reality-Checker Production Certification (`TestingRealityChecker`)
- **Assigned Agent**: `agency-reality-checker` (`/Users/sadiqadeyanju/.gemini/config/skills/agency-reality-checker/SKILL.md`)
- **Agent Prompt for Gemini 3.8 Flash**:
  `"Act as TestingRealityChecker. Execute mandatory reality check commands across the entire repository: verify all 14 Rust GUI apps + 13 CLI binaries compile and pass tests, verify all 21 web portal routes render, cross-check public/qa-screenshots/test-results.json, and write the final certification report in project-docs/reality-check-certification.md."`
- **Files to Create/Edit**:
  - `[NEW]` `project-docs/reality-check-certification.md`
- **Acceptance Criteria & Verification**:
  - `cargo test --workspace` passes 100%; `cargo clippy --workspace --all-targets -- -D warnings` passes with 0 warnings; all 42 tasks marked `[x]`.
