# CloudSecure Suite: Complete 14-Application Technical Specification

> **Authored by**: `agency-cloud-security-architect`, `agency-desktop-app-engineer`, `agency-webassembly-engineer`, `agency-mcp-builder`  
> **Scope**: Complete domain, Rust crate, `egui` + `wgpu` UI, CLI, JSON-RPC, and Model Context Protocol (MCP) specifications for `launchersecure` and all 13 CloudSecure applications.

---

## Shared 4-Way Control Contract (Every Application)

Every application in the CloudSecure suite implements the `CloudSecureAppEngine` trait from `crates/cloudsecure-automation`:

```rust
pub trait CloudSecureAppEngine: Send + Sync + 'static {
    type Command: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync;
    type StateSnapshot: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    fn app_metadata(&self) -> AppCatalogEntry;
    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error>;
    fn undo(&mut self) -> Result<Option<CommandReceipt>, Self::Error>;
    fn redo(&mut self) -> Result<Option<CommandReceipt>, Self::Error>;
    fn snapshot(&self) -> Self::StateSnapshot;
    fn export_sarif(&self) -> cloudsecure_types::SarifReport;
}
```

This guarantees that every single feature in every app is accessible via:
1. **Native Desktop GUI (`egui` + `eframe` + `wgpu`)**: macOS, Windows, Linux, FreeBSD.
2. **Browser WebAssembly (`trunk` + WebGPU/WebGL2)**: Runs offline inside the browser at `/wasm/<app-slug>/index.html`.
3. **Headless CLI (`<app>-cli`)**: Fast terminal execution with `--format {table,json,sarif,csv,csec}` and non-zero exit codes on policy failure.
4. **JSON-RPC & MCP Server (`<app>-cli --mcp` / `--json-rpc`)**: Exposes `execute_command`, `query_rql`, `get_findings`, `generate_remediation`, and `render_offscreen_png` to AI agents.

---

## App 00: `launchersecure` (Suite Manager & Auto-Updater)

- **Replicates**: `storytold/craft-launcher` (`ArtCraft Launcher`)
- **Crates**: `apps/launchersecure` (depends on `cloudsecure-ui`, `cloudsecure-types`, `cloudsecure-automation`)
- **Core Capabilities**:
  1. **Catalog Views**: Instant toggle in the top HUD bar between **Card Grid View** (icon, CNAPP pillar badge, installed version, latest version, SHA-256 verification pill, `Install` / `Update` / `Open` button) and **Sortable Table View** (columns: `App`, `Pillar`, `Status`, `Installed`, `Latest`, `Released`, `Size`, `SHA-256`, `Action`).
  2. **OS & CPU Package Resolver**: Detects `(os, arch)` (`macos-aarch64`, `macos-x86_64`, `windows-x86_64`, `windows-aarch64`, `linux-x86_64`, `linux-aarch64`, `freebsd-x86_64`, `wasm32`) and selects the matching release artifact (`.dmg`, `.msi`, `.deb`, `.rpm`, `.AppImage`, Flatpak, or portable `.tar.zst`).
  3. **Cryptographic Integrity Gate**: Downloads to `<data_dir>/staging/<artifact>.part`, computes streaming `sha2::Sha256`, verifies against the Ed25519-signed `manifest.json` (`ed25519-dalek`), checks process table so running apps are never overwritten, and preserves `N-1` binary for 1-click rollback.
  4. **System Tray & Menu Bar**: Quick-launch menu listing all installed CloudSecure apps, global posture status summary, and `Update All` action.
  5. **10-Locale i18n**: `Auto`, `en`, `pt-BR`, `cs`, `fr`, `de`, `hu`, `ja`, `pl`, `ru`, `zh-CN`, `es` via `CLOUDSECURE_LOCALE` env var or `?lang=` query parameter on web.
  6. **Rotating Structured Logs**: Writes to `logs/launchersecure.log` (plus `.1.log` and `.2.log`) inside platform data directory.

---

## App 01: `PostureSecure` (CSPM: Cloud Security Posture Management)

- **Replicates**: CSPM (Cloud Security Posture Management)
- **Accent Token (`--app-ink`)**: Light `#0F52BA` / Dark `#5C9DFF` | **Icon**: Isometric Shield Grid
- **Crates**: `apps/posturesecure`, `apps/posturesecure-cli`
- **Domain Engine & Structs**:
  - `CloudResourceInventory`: Ingests AWS Config, Azure Resource Graph, GCP Asset Inventory, OCI, and Kubernetes snapshots into `cloudsecure-graph`.
  - `ComplianceMapper`: Evaluates 60+ built-in CSPM policies across **CIS AWS v3.0**, **CIS Azure v2.1**, **CIS GCP v2.0**, **NIST 800-53 Rev 5**, **SOC 2 Type II**, **PCI-DSS v4.0**, **HIPAA**, and **GDPR**.
  - `DriftDetector`: Compares live/snapshot resource state against baseline `.csec` state or Terraform state, flagging unauthorized out-of-band console mutations.
  - `RemediationSynthesizer`: Generates deterministic AWS CLI, `gcloud`, `az`, and Terraform HCL patch diffs for every misconfiguration (e.g., S3 Block Public Access, RDS encryption, IMDSv2 hop-limit enforcement, Security Group `0.0.0.0/0` restriction).
- **Sample RQL Queries Executed**:
  - `config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = publicAccessBlockConfiguration.restrictPublicBuckets is false`
  - `config from cloud.resource where api.name = 'aws-ec2-instance' and json.rule = metadataOptions.httpTokens != 'required'`
- **`egui` Workbench Layout**:
  - **Top Bar**: RQL query input with syntax highlighting & autocomplete, Cloud Provider filter (`All`, `AWS`, `Azure`, `GCP`, `K8s`), Compliance Framework selector, Theme toggle.
  - **Left Rail (`240px`)**: Compliance Framework tree with real-time pass/fail percentages per control family (`IAM`, `Storage`, `Networking`, `Logging`, `Compute`, `KMS`).
  - **Center Canvas**: Split between Compliance Posture Matrix and Virtualized Resource Findings Table (`Severity`, `Policy ID`, `Resource ARN/ID`, `Region`, `Account`, `Drift Status`, `Framework Controls`).
  - **Right Inspector (`340px`)**: Resource JSON configuration viewer + Unified Diff Remediation Patch (`Terraform HCL` / `CLI`) with `[Copy Patch]` and `[Export .patch]` buttons.
  - **Bottom Console (`160px`)**: RQL execution plan timing, AST inspector, and JSON-RPC/MCP audit log.
- **UI States (R-27)**:
  - *Empty*: `"No cloud resource snapshot loaded. Load the bundled multi-cloud CIS benchmark corpus (420 resources across AWS, Azure, GCP) or import a cloud snapshot directory."` + `[Load Bundled Multi-Cloud Corpus]`.
  - *Loading*: `"Evaluating 64 CSPM RQL policies across 420 cloud resources..."` with progress bar.
  - *Error*: Displays exact JSON/HCL parse line/column error and `[Reset to Last Valid Snapshot]`.
- **CLI & MCP Interface**:
  - CLI: `posturesecure-cli scan --input ./fixtures/aws-prod.json --framework cis-aws-3.0 --rql "config from ..." --format sarif`
  - MCP Tools: `posture_run_rql`, `posture_evaluate_compliance`, `posture_detect_drift`, `posture_generate_remediation`.

---

## App 02: `DataSecure` (DSPM: Data Security Posture Management & DDR)

- **Replicates**: DSPM (Data Security Posture Management & DDR) (Dig Security)
- **Accent Token (`--app-ink`)**: Light `#0D6E52` / Dark `#34D399` | **Icon**: Layered Cylinder Vault
- **Crates**: `apps/datasecure`, `apps/datasecure-cli`
- **Domain Engine & Structs**:
  - `DataAssetCatalog`: Discovers managed and shadow data stores (S3, GCS, Azure Blob, RDS, DynamoDB, Snowflake, BigQuery, local/mounted buckets and parquet/CSV/JSONL dumps).
  - `SensitiveDataClassifier`: Linear-time `aho-corasick` + `regex` + Shannon entropy + Luhn/IBAN/SSN checksum verifier that classifies:
    - **PII**: SSN, Passport, Driver License, Email, Phone, National IDs
    - **PCI**: Credit Card PANs (Luhn-validated), CVV patterns, Track data
    - **PHI**: ICD-10/SNOMED markers, Medical Record Numbers, HIPAA identifiers
    - **Secrets & Keys**: AWS Access Keys, GCP Service Account JSON, Private Keys (`PEM`), JWTs, Stripe/GitHub tokens
    - **IP & Financial**: Source code markers, M&A/financial schema signatures
  - `Mandatory SecretRedactor`: Masks raw hits immediately into `RedactedSample` (`"4532-****-****-8901"`, SHA-256 fingerprint) using `zeroize` so raw sensitive strings never persist in memory or disk.
  - `DataLineageAndDdrEngine`: Tracks cross-region replication, unencrypted staging copies ("shadow data"), public bucket exposure of classified stores, and anomalous bulk read/exfiltration events (DDR).
- **Sample RQL Queries Executed**:
  - `data from cloud.data_store where data.classification contains 'PCI' and exposure.public = true`
  - `data from cloud.data_store where data.shadow_copy = true and encryption.kms_cmk = false`
- **`egui` Workbench Layout**:
  - **Left Rail**: Data Classification Taxonomy filter (`PII`, `PCI`, `PHI`, `Secrets`, `IP`) + Data Store Type (`Object Storage`, `Relational DB`, `Data Warehouse`, `Shadow Backup`).
  - **Center Canvas**: Dual-mode **Data Store Risk Matrix** and **Data Lineage Flow Graph** (`wgpu` directed flow from Production DB -> Analytics Staging -> Public Bucket).
  - **Right Inspector**: Redacted classification breakdown (hit counts, confidence score, Luhn/checksum validation badge, encryption status, IAM principals with `s3:GetObject` / `rds:Connect` access).
- **CLI & MCP Interface**:
  - CLI: `datasecure-cli classify --target ./sample-data-lake --redact-strict --format sarif`
  - MCP Tools: `dspm_scan_datastore`, `dspm_query_lineage`, `dspm_list_exposed_pii`, `dspm_evaluate_ddr_events`.

---

## App 03: `WorkloadSecure` (CWPP: Cloud Workload, Container & Runtime Protection)

- **Replicates**: CWPP (Cloud Workload Protection & Container Security)
- **Accent Token (`--app-ink`)**: Light `#8B3A0E` / Dark `#FB923C` | **Icon**: Hexagonal Pod Matrix
- **Crates**: `apps/workloadsecure`, `apps/workloadsecure-cli`
- **Domain Engine & Structs**:
  - `OciImageInspector`: Pure Rust OCI/Docker image manifest, config, and layer tarball analyzer (`tar` + `flate2` + `zstd`). Extracts installed packages (`dpkg`, `apk`, `rpm`, `Cargo.lock`, `package.json`, Python `METADATA`, Go buildinfo) per layer.
  - `VulnerabilityMatcher`: Matches extracted package PURLs against bundled OSV/CVE vulnerability index with CVSS v3.1 score, EPSS exploitability, CISA KEV status, and fixed-version layer attribution.
  - `RuntimeBehavioralProfiler`: Models container/host runtime profiles (`ProcessAllowlist`, `NetworkSocketPolicy`, `FilesystemWritePaths`, `LinuxCapabilities`, `SyscallProfile`). Ingests Falco/eBPF/Auditd/Kubernetes runtime event streams to flag container escapes, unexpected shells (`/bin/sh` spawned by `nginx`), cryptominers, and root privilege escalations.
  - `ServerlessAndVmScanner`: Audits AWS Lambda / Cloud Run package bundles and overpermissive execution roles, plus VM SSH/IMDSv1 posture.
- **`egui` Workbench Layout**:
  - **Left Rail**: Workload Hierarchy (`OCI Images`, `Kubernetes Clusters & Pods`, `VMs / Hosts`, `Serverless Functions`).
  - **Center Canvas**: **Interactive Layer-by-Layer Image X-Ray** (shows exact Dockerfile command per layer, size weight, CVE count by severity, and secret leaks in deleted layers) + **Runtime Behavioral Timeline**.
  - **Right Inspector**: CVE detail card (CVSS vector, fixed version, base image upgrade recommendation) and generated Kubernetes `SecurityContext` / `SeccompProfile` / `AppArmor` hardening YAML.
- **CLI & MCP Interface**:
  - CLI: `workloadsecure-cli image-scan --oci-dir ./fixtures/oci-nginx --fail-on critical`
  - MCP Tools: `cwpp_scan_oci_image`, `cwpp_audit_k8s_pod_security`, `cwpp_analyze_runtime_events`, `cwpp_generate_seccomp_profile`.

---

## App 04: `IdentitySecure` (CIEM: Cloud Infrastructure Entitlement Management)

- **Replicates**: CIEM (Cloud Infrastructure Entitlement Management)
- **Accent Token (`--app-ink`)**: Light `#6B21A8` / Dark `#C084FC` | **Icon**: Key-Graph Node
- **Crates**: `apps/identitysecure`, `apps/identitysecure-cli`
- **Domain Engine & Structs**:
  - `EffectivePermissionSolver`: Evaluates the full policy algebra across AWS IAM Identity Policies + Resource Policies (S3/KMS) + Service Control Policies (SCPs) + Permission Boundaries + Session Policies, Azure RBAC, GCP IAM, and Kubernetes RBAC (`ClusterRoleBinding` / `RoleBinding`).
  - `PrivilegeEscalationDetector`: Detects all 21+ cloud IAM privilege escalation vectors (e.g., `iam:PassRole` + `ec2:RunInstances`, `iam:CreatePolicyVersion`, `lambda:UpdateFunctionCode`, `sts:AssumeRole` cross-account chains).
  - `EntitlementRightSizer`: Correlates granted actions against 90-day CloudTrail / Activity Log usage records to compute the **Permission Gap** (Granted vs. Used) and synthesizes a least-privilege JSON IAM policy and Terraform diff.
- **Sample RQL Queries Executed**:
  - `iam from cloud.entitlements where action.effective contains 's3:DeleteBucket' and principal.type = 'AssumedRole' and action.last_used_days > 90`
  - `iam from cloud.entitlements where escalation.path_exists = true and target.privilege = 'Admin'`
- **`egui` Workbench Layout**:
  - **Left Rail**: Principal Directory (`Human Users`, `Service Accounts / Roles`, `Cross-Account Trusts`, `Federated OIDC`, `K8s ServiceAccounts`).
  - **Center Canvas**: **Interactive Net-Effective Permission Graph** (`Principal -> Group/Role -> Policy/SCP -> Effective Action -> Resource`) + **Granted vs. Used Heatmap**.
  - **Right Inspector**: Least-Privilege Policy Synthesizer showing side-by-side diff of Current Overpermissive Policy vs. Right-Sized Policy based on actual audit trail activity.
- **CLI & MCP Interface**:
  - CLI: `identitysecure-cli analyze --iam-bundle ./fixtures/aws-iam.json --cloudtrail ./fixtures/trail.json`
  - MCP Tools: `ciem_compute_effective_permissions`, `ciem_find_escalation_paths`, `ciem_synthesize_least_privilege`.

---

## App 05: `CodeSecure` (ASPM & Code Security: Shift-Left IaC Policy Engine)

- **Replicates**: ASPM (Application Security & IaC Static Analysis)
- **Accent Token (`--app-ink`)**: Light `#1E5631` / Dark `#4ADE80` | **Icon**: AST Brackets `</>`
- **Crates**: `apps/codesecure`, `apps/codesecure-cli`
- **Domain Engine & Structs**:
  - `IacAstScanner`: Multi-format Infrastructure-as-Code parser and graph evaluator supporting **Terraform HCL (`.tf`)**, **Terraform Plan JSON**, **CloudFormation (YAML/JSON)**, **Kubernetes Manifests & Helm Charts**, **Dockerfiles**, **Azure ARM / Bicep**, and **GitHub Actions / GitLab CI workflows** (`.github/workflows/*.yml`).
  - `IacPolicyEngine`: Implements `IAC_AWS_*`, `IAC_AZURE_*`, `IAC_GCP_*`, `IAC_K8S_*`, `IAC_DOCKER_*`, and `IAC_GHA_*` rule IDs with graph-aware cross-resource linking (e.g., verifying whether an `aws_s3_bucket` has a corresponding `aws_s3_bucket_public_access_block` resource in the same module).
  - `ScaAndSbomEngine`: Parses `Cargo.lock`, `package-lock.json`, `pnpm-lock.yaml`, `go.sum`, `requirements.txt`, and `pom.xml`, evaluates transitive dependency CVEs, checks license compliance (`GPL`/`AGPL` copyleft alerts), and exports **CycloneDX 1.5** and **SPDX 2.3** SBOMs.
  - `GitSecretScanner`: High-speed entropy + pattern scanner with pre-commit hook generator and line-level redaction.
- **`egui` Workbench Layout**:
  - **Left Rail**: Repository File Tree with inline finding count badges (`Terraform`, `K8s`, `Dockerfile`, `CI Workflows`, `Lockfiles`).
  - **Center Canvas**: **Split AST Code Editor & Resource Dependency Graph** highlighting the exact offending HCL/YAML lines with inline `CKV_*` diagnostics.
  - **Right Inspector**: One-click **Auto-Fix Code Diff** that inserts the missing secure attributes (and validates that the patched HCL/YAML parses cleanly) + SBOM exporter.
- **CLI & MCP Interface**:
  - CLI: `codesecure-cli check --dir ./infra --framework terraform,kubernetes,github_actions --export-sbom cyclonedx.json`
  - MCP Tools: `aspm_scan_iac_directory`, `aspm_generate_iac_autofix`, `aspm_generate_sbom`, `aspm_scan_secrets`.

---

## App 06: `WaasSecure` (WAAS: Web Application and API Security)

- **Replicates**: WAAS (Web Application & API Security)
- **Accent Token (`--app-ink`)**: Light `#9D174D` / Dark `#F472B6` | **Icon**: Wave Inspection Gate
- **Crates**: `apps/waassecure`, `apps/waassecure-cli`
- **Domain Engine & Structs**:
  - `OpenApiSchemaAuditor`: Parses OpenAPI 3.0/3.1 specs and compares them against captured HTTP/HTTPS traffic logs (HAR / Envoy / NGINX / WAF logs) to discover **Shadow APIs** (undocumented endpoints), **Zombie APIs** (deprecated endpoints still serving traffic), unauthenticated routes, and mass-assignment schema violations.
  - `Layer7InspectionEngine`: Pure Rust WAF rule engine evaluating requests/responses against **OWASP Top 10 (2021)** and **OWASP API Security Top 10 (2023)**: SQL Injection (tokenized lexical analysis), XSS, SSRF (including cloud metadata `169.254.169.254` / `[fd00:ec2::254]` payloads), Path Traversal, Log4Shell/Command Injection, BOLA/IDOR patterns, and weak JWT signatures (`alg: none`, expired claims).
  - `VirtualPatchStudio`: Generates Envoy HTTP Filter / ModSecurity SecRule / Cloudflare / AWS WAFv2 JSON rules to block discovered exploit vectors immediately without waiting for application code redeployment.
- **`egui` Workbench Layout**:
  - **Left Rail**: API Endpoint Tree (`Documented Routes`, `Shadow/Undocumented Routes`, `WAF Rulesets`, `Bot & Rate Limit Policies`).
  - **Center Canvas**: **API Traffic & Payload Replay Inspector** (shows HTTP request/response headers, body token breakdown, matched OWASP rule, and schema conformance check).
  - **Right Inspector**: Virtual Patch Rule Generator (`Envoy`, `ModSecurity`, `AWS WAFv2`) + OpenAPI spec hardening diff.
- **CLI & MCP Interface**:
  - CLI: `waassecure-cli inspect --openapi ./api-spec.yaml --traffic ./access-logs.jsonl --format sarif`
  - MCP Tools: `waas_discover_shadow_apis`, `waas_inspect_http_payload`, `waas_generate_virtual_patch`.

---

## App 07: `ThreatSecure` (CDR: Cloud Detection, Response & MITRE ATT&CK Workbench)

- **Replicates**: CDR (Cloud Detection & Response) / Cortex Cloud Detection & Response
- **Accent Token (`--app-ink`)**: Light `#A81E23` / Dark `#F87171` | **Icon**: Radar Pulse Crosshair
- **Crates**: `apps/threatsecure`, `apps/threatsecure-cli`
- **Domain Engine & Structs**:
  - `CloudAuditStreamEngine`: High-throughput parser and correlation engine for **AWS CloudTrail**, **AWS GuardDuty**, **VPC Flow Logs**, **GCP Cloud Audit Logs**, **Azure Activity Logs**, and **Kubernetes Audit Logs**.
  - `AttackChainCorrelator`: Stitches discrete low-severity events across identity, control plane, and network logs into multi-stage **Incident Storylines** mapped to the **MITRE ATT&CK for Cloud (IaaS & Containers)** matrix (`Initial Access`, `Execution`, `Persistence`, `Privilege Escalation`, `Defense Evasion`, `Credential Access`, `Discovery`, `Lateral Movement`, `Exfiltration`).
  - `ContainmentPlaybookGenerator`: Generates step-by-step forensic containment commands (revoke active STS sessions, attach quarantine `DenyAll` IAM policy, isolate instance Security Group, trigger EBS forensic snapshot).
- **Sample RQL Queries Executed**:
  - `event from cloud.audit_logs where operation in ('CreateAccessKey', 'PutUserPolicy', 'StopLogging') and source.ip.asn_suspicious = true`
- **`egui` Workbench Layout**:
  - **Left Rail**: Active Incidents Queue (sorted by blast radius) + MITRE ATT&CK Tactic Filter.
  - **Center Canvas**: **Interactive MITRE ATT&CK Cloud Matrix** + **Chronological Incident Kill-Chain Timeline** linking actor IP, principal ARN, API call, and target resource.
  - **Right Inspector**: Raw CloudTrail/Audit event JSON + Forensic Containment Playbook with safety dry-run preview.
- **CLI & MCP Interface**:
  - CLI: `threatsecure-cli hunt --logs ./fixtures/cloudtrail-incident.jsonl --mitre-matrix`
  - MCP Tools: `cdr_correlate_audit_logs`, `cdr_map_mitre_attack`, `cdr_generate_containment_playbook`.

---

## App 08: `GraphSecure` (Cloud Security Graph & Attack Path Simulator)

- **Replicates**: Attack Path Analysis & Cloud Exposure Graph
- **Accent Token (`--app-ink`)**: Light `#4338CA` / Dark `#818CF8` | **Icon**: Directed Acyclic Graph
- **Crates**: `apps/graphsecure`, `apps/graphsecure-cli`
- **Domain Engine & Structs**:
  - `ToxicCombinationSolver`: Queries `cloudsecure-graph` using multi-hop graph pattern matching and weighted Dijkstra/Yen's $k$-shortest paths to find **Toxic Combinations** where multiple individual findings combine into a critical breach path towards a **Crown Jewel** asset (e.g., `Internet -> Public ALB -> Container with CVE-2024-XXXX -> Instance Profile with s3:* -> Production Customer PII Bucket`).
  - `ChokePointOptimizer`: Calculates the **Betweenness Centrality** and minimum edge-cut across all active attack paths so SecOps teams know which **single remediation** breaks the maximum number of breach paths simultaneously.
- **`egui` Workbench Layout**:
  - **Left Rail**: Attack Path Templates (`Internet to Crown Jewel Data`, `Container Escape to Cloud Admin`, `CI/CD Runner to Prod Secrets`, `Cross-Account Lateral Movement`) + Choke Point Ranking list.
  - **Center Canvas**: **GPU-Accelerated (`wgpu`) Force-Directed & Layered DAG Viewport** with smooth pan/zoom, blast-radius highlighting, and interactive "What-If Remediation" node/edge toggling (click any edge to simulate fixing a vulnerability or revoking an IAM role and watch downstream attack paths disappear in real time).
  - **Right Inspector**: Step-by-step Attack Path hop breakdown + Choke Point ROI score.
- **CLI & MCP Interface**:
  - CLI: `graphsecure-cli paths --snapshot ./fixtures/multi-cloud.csec --target crown-jewels --choke-points`
  - MCP Tools: `graph_find_attack_paths`, `graph_compute_choke_points`, `graph_simulate_remediation`.

---

## App 09: `NetSecure` (CNS: Cloud Network Security & Zero-Trust Microsegmentation)

- **Replicates**: CNS (Cloud Network Security & Microsegmentation)
- **Accent Token (`--app-ink`)**: Light `#0E606B` / Dark `#22D3EE` | **Icon**: Segmented Mesh Topology
- **Crates**: `apps/netsecure`, `apps/netsecure-cli`
- **Domain Engine & Structs**:
  - `NetworkReachabilitySolver`: Symbolic CIDR / port-range set solver (interval trees over IPv4/IPv6 + TCP/UDP port ranges) that computes exact **Net Effective Reachability** across VPC/VNet Route Tables, Internet Gateways, NAT Gateways, Transit Gateways, VPC Peering, Security Groups, Network ACLs, and Kubernetes `NetworkPolicy` manifests without sending a single packet.
  - `MicrosegmentationSynthesizer`: Ingests observed VPC Flow Logs / Cilium / eBPF flow records, compares observed legitimate service-to-service flows against permitted security group / K8s network policy rules, and synthesizes **Zero-Trust Default-Deny** Kubernetes `NetworkPolicy` YAML and Terraform `aws_security_group_rule` diffs.
- **Sample RQL Queries Executed**:
  - `network from vpc.flow_record where src.public = true and dest.port in (22, 3389, 5432, 6379) and action = 'ACCEPT'`
- **`egui` Workbench Layout**:
  - **Left Rail**: VPC / VNet / Cluster Topology Tree + Reachability Query Builder (`Source -> Destination : Port`).
  - **Center Canvas**: **East-West Traffic Matrix & VPC Topology Map** showing permitted vs. observed traffic edges.
  - **Right Inspector**: Symbolic Path Trace (shows exact Route Table entry, NACL rule #, and Security Group rule ID permitting or blocking the packet) + Zero-Trust Kubernetes `NetworkPolicy` generator.
- **CLI & MCP Interface**:
  - CLI: `netsecure-cli reachability --topology ./fixtures/vpc.json --src 0.0.0.0/0 --dst i-prod-db --port 5432`
  - MCP Tools: `cns_verify_reachability`, `cns_analyze_flow_logs`, `cns_synthesize_network_policy`.

---

## App 10: `AiSecure` (AI-SPM: AI Security Posture Management)

- **Replicates**: AI-SPM (AI Security Posture Management)
- **Accent Token (`--app-ink`)**: Light `#7C2D12` / Dark `#FDBA74` | **Icon**: Tensor Lattice
- **Crates**: `apps/aisecure`, `apps/aisecure-cli`
- **Domain Engine & Structs**:
  - `AiInventoryDiscovery`: Inventories cloud AI/ML assets (AWS Bedrock, SageMaker, Azure OpenAI, GCP Vertex AI, vector databases like Pinecone/pgvector/OpenSearch, and local/repo model files).
  - `ModelArtifactScanner`: Audits model weight formats, flagging unsafe Python `pickle` / `pytorch_model.bin` deserialization opcodes (`GLOBAL`, `REDUCE`, `STACK_GLOBAL` arbitrary code execution risks) and verifying safe `safetensors` / `GGUF` headers and SHA-256 model cards.
  - `AiDataAndGuardrailAuditor`: Traces whether sensitive DSPM-classified datasets (`PII`/`PHI`/`Secrets`) are wired into RAG vector indexes or fine-tuning buckets, checks LLM endpoint egress/IAM permissions (excessive tool agency), and evaluates OWASP Top 10 for LLM Applications controls.
- **`egui` Workbench Layout**:
  - **Left Rail**: AI Asset BOM (`Foundation Models`, `Fine-Tuned Checkpoints`, `RAG Vector Stores`, `AI Agents & Plugins`).
  - **Center Canvas**: **AI Pipeline Supply-Chain & RAG Lineage Map** (`Training/RAG Corpus -> Embedding Job -> Model Endpoint -> Agent Tool Permissions`).
  - **Right Inspector**: Pickle Opcode Safety Inspector, OWASP LLM Top 10 checklist, and Bedrock/Vertex guardrail configuration generator.
- **CLI & MCP Interface**:
  - CLI: `aisecure-cli audit --ai-bom ./fixtures/ai-pipeline.json --scan-models ./models`
  - MCP Tools: `aispm_discover_ai_bom`, `aispm_scan_model_pickle`, `aispm_audit_rag_data_exposure`.

---

## App 11: `SupplySecure` (Software Supply Chain, SLSA & CI/CD Security)

- **Replicates**: Software Supply Chain Security & SLSA Provenance
- **Accent Token (`--app-ink`)**: Light `#374151` / Dark `#9CA3AF` | **Icon**: Interlocking Chain Link
- **Crates**: `apps/supplysecure`, `apps/supplysecure-cli`
- **Domain Engine & Structs**:
  - `PipelinePostureAuditor`: Audits GitHub Actions, GitLab CI, and Jenkins pipelines for supply-chain attack vectors: unpinned third-party actions (`uses: owner/action@main` instead of full 40-char commit SHA), `pull_request_target` script injection, overpermissive `GITHUB_TOKEN` permissions (`permissions: write-all`), missing OIDC federation, and self-hosted runner persistence risks.
  - `SlsaAndAttestationVerifier`: Verifies **SLSA v1.0** provenance predicates (`in-toto` statement JSON), Ed25519/Sigstore artifact signatures, and dependency confusion / typosquatting risks across Cargo, npm, and PyPI registries.
- **`egui` Workbench Layout**:
  - **Left Rail**: CI/CD Workflows, Build Runners, Registries, and Release Artifacts.
  - **Center Canvas**: **End-to-End Software Supply Chain Graph** (`Developer Commit -> CI Workflow -> Build Runner -> Container/Binary Artifact -> SLSA Provenance`).
  - **Right Inspector**: Auto-pinned GitHub Actions YAML diff (replaces mutable tags with verified commit SHAs + minimal `permissions:` block) and SLSA Level 3 readiness scorecard.
- **CLI & MCP Interface**:
  - CLI: `supplysecure-cli audit-ci --workflows ./.github/workflows --verify-slsa ./provenance.intoto.jsonl`
  - MCP Tools: `supply_audit_ci_workflows`, `supply_pin_github_actions`, `supply_verify_slsa_provenance`.

---

## App 12: `PolicySecure` (Unified RQL & Policy-as-Code Studio)

- **Replicates**: Policy-as-Code Studio & Custom RQL Workbench
- **Accent Token (`--app-ink`)**: Light `#854D0E` / Dark `#FACC15` | **Icon**: Rule Scales & Balance
- **Crates**: `apps/policysecure`, `apps/policysecure-cli`
- **Domain Engine & Structs**:
  - `RqlIdeEngine`: Interactive parser, formatter, static type-checker, autocomplete provider, and explain-plan profiler for all 5 CloudSecure RQL query families (`config`, `network`, `event`, `iam`, `data`).
  - `PolicyRulePackManager`: Authors, validates, unit-tests, and packages custom YAML/RQL policy packs with test fixtures (`pass_fixtures`, `fail_fixtures`), severity scoring, compliance control mappings, and remediation templates.
- **`egui` Workbench Layout**:
  - **Left Rail**: Policy Pack Explorer (`Built-in 150+ Policies`, `Custom Policy Packs`, `Unit Test Suites`).
  - **Center Canvas**: **Split RQL/Policy Editor & Live AST + Execution Explain Plan** with instant sub-millisecond evaluation against loaded cloud test fixtures.
  - **Right Inspector**: Policy Unit Test Runner (`PASS`/`FAIL` assertions against positive and negative resource fixtures) + Policy Pack Exporter (`.csec-policy.yaml`).
- **CLI & MCP Interface**:
  - CLI: `policysecure-cli test --pack ./policies/custom-pack.yaml --benchmark`
  - MCP Tools: `policy_parse_and_explain_rql`, `policy_run_unit_tests`, `policy_validate_pack`.

---

## App 13: `ComplianceSecure` (Executive Command Center & Compliance Audit Exporter)

- **Replicates**: Executive Command, Multi-Framework Compliance & Audit Reporting
- **Accent Token (`--app-ink`)**: Light `#115E59` / Dark `#2DD4BF` | **Icon**: Telemetry Ledger
- **Crates**: `apps/compliancesecure`, `apps/compliancesecure-cli`
- **Domain Engine & Structs**:
  - `UnifiedPostureAggregator`: Ingests `.csec` snapshots and SARIF outputs from all 12 sibling CloudSecure apps into a single deduplicated **CNAPP Risk Ledger**.
  - `AuditBundleCompiler`: Compiles deterministic, cryptographically signed **Compliance Evidence Bundles** for **SOC 2 Type II**, **ISO 27001:2022**, **PCI-DSS v4.0**, **HIPAA**, **NIST CSF 2.0**, and **FedRAMP Moderate** in HTML, Markdown, CSV, JSON, and SARIF 2.1.0 formats, complete with SHA-256 evidence manifests.
- **`egui` Workbench Layout**:
  - **Product Lens Decision (per `antislop-ui` & `agency-ui-finish-gate-reviewer`)**: Instead of a generic 4-stat-card dashboard, the primary first-read object is the **Prioritized Top-10 Breach-Stopping Remediation Queue** ranked by cross-pillar blast-radius reduction across all 12 modules, paired with the **Framework Audit Readiness Matrix**.
  - **Left Rail**: Cloud Accounts / Business Units + Compliance Frameworks (`SOC 2`, `ISO 27001`, `PCI-DSS v4`, `NIST 800-53`, `HIPAA`).
  - **Center Canvas**: **Cross-Pillar Remediation Priority Queue** + **Control-by-Control Audit Evidence Table**.
  - **Right Inspector**: Evidence Bundle Preview & Signed Export Generator (`Export SOC 2 Evidence Package`).
- **CLI & MCP Interface**:
  - CLI: `compliancesecure-cli export-audit --snapshot ./fixtures/multi-cloud.csec --framework soc2 --out ./audit-bundle`
  - MCP Tools: `pulse_aggregate_posture`, `pulse_prioritize_remediations`, `pulse_export_compliance_bundle`.
