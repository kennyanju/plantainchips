# CloudSecure Suite: 80% Most-Used Features Specification

> **Scope**: Pareto (80/20) practitioner feature inventory across all 14 mirrored applications in CloudSecure (PlantainChips).

---

## 1. Executive Summary & Architecture

Each of the 14 applications in the CloudSecure suite mirrors two production benchmarks:
1. **UX & Runtime Shell**: storytold/craft-launcher and getartcraft.com (100% pure Rust engines with 4-way control across GUI, CLI, JSON-RPC, and Model Context Protocol).
2. **Security Domain Capabilities**: The 13 core modules of an enterprise Cloud-Native Application Protection Platform (Prisma Cloud, Cortex CDR, Checkov/Bridgecrew, Dig Security DSPM, Twistlock CWPP, Aporeto CNS, and Cider Supply Chain Security).

---

## 2. 80% Most-Used Feature Catalog (All 14 Apps)

### App 00: LauncherSecure (Mirrors storytold/craft-launcher)
1. **Catalog View Switcher**: Instant toggle between 2-/3-Column Card Grid and Sortable Technical Table (#, Application, Pillar, Installed, Latest, Size, SHA-256, Status, Action).
2. **Search, Pillar Filter & OS/Arch Selector**: Filter by keyword or CNAPP pillar (ALL, POSTURE, DATA, WORKLOAD, IDENTITY, CODE, NETWORK, RUNTIME, GOVERNANCE) and target platform (macos-aarch64, macos-x86_64, linux-x86_64, windows-x86_64, wasm32).
3. **Cryptographic Verification & Quarantine Engine**: Stream-hash artifacts with SHA-256, verify against Ed25519 release signatures, and automatically quarantine any artifact with a digest mismatch (AppStatus::Quarantined).
4. **Lifecycle State Machine & N-1 Rollback**: Execute InstallApp, UpdateAll, and RollbackApp commands while preserving the previous version digest in rollback_points.
5. **Workspace Posture Pulse**: Display live finding counts across all 13 apps in the launcher header and allow 1-click navigation into any app workbench.

### App 01: PostureSecure (Mirrors Prisma Cloud CSPM)
1. **Multi-Cloud Resource Inventory Explorer**: Filter and inspect AWS, Azure, GCP, and Kubernetes resources by provider, service type, account/subscription ID, region, and tags.
2. **Expanded Standard CSPM Policy Pack (35+ Core Rules)**:
   - AWS: S3 public access block (CIS-AWS-3.0-2.1.1), S3 MFA delete & versioning, RDS storage encryption (CIS-AWS-3.0-2.2.1), RDS public accessibility, EC2 IMDSv2 enforcement, EBS encryption by default, Security Group open SSH 22 / RDP 3389 (CIS-AWS-3.0-4.1, 4.2), CloudTrail multi-region & log validation, KMS automatic key rotation, IAM root MFA & access key rotation.
   - Azure: Storage account HTTPS transfer (CIS-AZURE-2.1-1), Storage public blob access disabled, Key Vault purge protection & expiration, NSG open RDP/SSH, SQL auditing & TDE enabled.
   - GCP: Uniform bucket-level access (CIS-GCP-2.0-3.1), Public bucket allUsers blocked, Cloud SQL public IP & SSL enforcement, Compute OS Login & shielded VM, GKE private cluster & workload identity.
3. **Ad-Hoc RQL config from Query Execution**: Live filter of resources and findings using RQL expressions.
4. **Baseline vs. Current State Drift Detection**: Identify out-of-band console modifications with attribute-level diff (baseline_value vs. current_value).
5. **Terraform HCL & CLI Remediation + Finding Suppression**: Copyable Terraform HCL and cloud CLI commands per finding, plus SuppressFinding { finding_id, reason }.

### App 02: DataSecure (Mirrors Prisma Cloud DSPM / Dig Security)
1. **Multi-Cloud & Shadow Data Store Inventory**: Track S3Bucket, AzureBlob, GcsBucket, RdsTable, SnowflakeWarehouse, BigQueryDataset, DynamoDbTable, and ShadowBackup stores.
2. **Multi-Class Sensitive Data Scanner**:
   - PII: US SSN (XXX-XX-XXXX), Email addresses, Phone numbers, Passport numbers, IBANs.
   - PCI: 13-19 digit Payment Card PANs verified with ISO/IEC 7812 Luhn checksum.
   - PHI: ICD-10 medical codes, Medical Record Numbers (MRN-*), HIPAA markers.
   - SECRET: AWS Access Keys (AKIA..., ASIA...), GitHub PATs (ghp_..., github_pat_...), Stripe live keys (sk_live_...), Slack tokens (xoxb-...), PEM private keys, and Shannon Entropy (H >= 4.5 bits/char on tokens >= 20 chars).
3. **Mandatory Zero-Leakage Redaction (SecretRedactor)**: Mask all matched samples (prefix-****-****-suffix) and compute SHA-256 fingerprints immediately upon detection.
4. **Data Lineage & Residency Auditor**: Model directed data replication edges (Source Store -> Target Store) to flag Production PII/PCI copied into unencrypted staging buckets or across sovereign regions.
5. **DDR Exposure & Exfiltration Evaluator**: Flag public sensitive buckets (DDR-DSPM-001), unencrypted shadow copies (DDR-DSPM-002), missing KMS CMK (DDR-DSPM-003), cross-region residency drift (DDR-DSPM-004), and bulk read exfiltration anomalies (DDR-DSPM-005).

### App 03: WorkloadSecure (Mirrors Prisma Cloud CWPP / Twistlock)
1. **OCI Container Layer-by-Layer Dissector**: Break down image layers by created_by Dockerfile command, byte size, installed packages, and secrets left in layers.
2. **Expanded CVE Vulnerability Matcher (15+ Core CVEs)**: Match OS (debian, alpine, ubuntu, rhel) and application (cargo, npm, pypi, golang) packages with CVSS v3.1, EPSS probability, CISA KEV status, and exact introduced_in_layer_index.
3. **Kubernetes Pod Security & Container Configuration Auditor**: Detect root execution (USER 0), privileged: true, hostNetwork: true, hostPID: true, dangerous capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN), missing read-only root filesystem, and mounted Docker socket.
4. **eBPF / Falco Runtime Behavioral Profiler**: Detect container shell spawns (/bin/sh, /bin/bash from nginx/node/java/python), cryptominer execution (xmrig, minerd, stratum+tcp), sensitive file reads (/etc/shadow, /proc/kcore, K8s service account token abuse), privilege escalation (sudo, setuid), and container escape syscalls (unshare, mount, ptrace).
5. **Hardening Profile Synthesizer**: Generate remediated Dockerfile instructions, Kubernetes SecurityContext YAML, and Linux SeccompProfile JSON.

### App 04: IdentitySecure (Mirrors Prisma Cloud CIEM)
1. **Net-Effective Permission Algebra Engine (P_eff)**: Resolve Inline Policies + Attached Managed Policies, intersect with Permission Boundary and Service Control Policies (SCPs), and subtract explicit Deny statements across AWS, Azure, GCP, and Kubernetes RBAC.
2. **15-Vector IAM Privilege Escalation Detector**: PassRole + EC2/Lambda/ECS/CloudFormation, CreatePolicyVersion, SetDefaultPolicyVersion, PutUserPolicy, AttachRolePolicy, CreateAccessKey, UpdateAssumeRolePolicy, UpdateFunctionCode, AssumeRole chain, K8s RBAC clusterroles/bind and pods/exec.
3. **Granted vs. Observed Usage Right-Sizer**: Compare granted effective actions against observed_actions from audit logs to compute entitlement_gap_percentage and flag dormant principals (last_active_days > 90).
4. **Cross-Account & Federated Trust Auditor**: Flag third-party trust policies missing sts:ExternalId and GitHub OIDC trust policies missing repository/branch conditions.
5. **Least-Privilege Policy Synthesizer**: Output scoped AWS IAM JSON policy and Terraform aws_iam_role_policy HCL restricted strictly to observed production actions.

### App 05: CodeSecure (Mirrors Checkov / Bridgecrew ASPM)
1. **Multi-Format IaC Static Policy Engine (20+ Rules)**:
   - Terraform: Public S3 ACL, missing S3 public_access_block, open SG port 22/3389 to 0.0.0.0/0, unencrypted RDS, RDS publicly_accessible, unencrypted EBS, EC2 IMDSv1, IAM policy Action=* and Resource=*, CloudWatch Log Group missing kms_key_id.
   - Kubernetes YAML: privileged: true, allowPrivilegeEscalation: true, runAsNonRoot: false, hostNetwork: true, hostPID: true, :latest image tag, missing resource limits.
   - Dockerfile: FROM ...:latest, USER root or missing USER, ADD remote URL, curl ... | sh, exposed port 22.
   - GitHub Actions YAML: pull_request_target with checkout, unpinned uses: owner/repo@branch, permissions: write-all, untrusted ${{ github.event... }} in run:.
2. **Source Secret & Entropy Scanner**: Scan all IaC and source files for hardcoded AWS keys, GitHub tokens, private keys, and connection credentials with line-number diagnostics.
3. **SCA Dependency & License Compliance Auditor**: Evaluate SbomComponent manifests for known vulnerable package versions and copyleft license violations (GPL-3.0, AGPL-3.0).
4. **Dual SBOM Exporter (CycloneDX 1.5 & SPDX 2.3)**: Export complete Software Bills of Materials with PURLs and SHA-256 component hashes.
5. **Auto-Fix Patch Generator**: Emit line-accurate unified diffs fixing each IaC misconfiguration.

### App 06: WaasSecure (Mirrors Prisma Cloud WAAS)
1. **OpenAPI 3.x vs. Live Traffic Drift & Shadow API Discovery**: Identify undocumented Shadow APIs (WAAS-API9-SHADOW), active Zombie/Deprecated APIs (WAAS-API9-ZOMBIE), and unauthenticated access (WAAS-API2-UNAUTH).
2. **OWASP Top 10 & API Security Top 10 Payload Inspection**:
   - WAAS-SQLI-001: SQL Injection (UNION SELECT, ' OR 1=1, --, SLEEP()
   - WAAS-XSS-001: Cross-Site Scripting (<script, javascript:, onerror=, onload=)
   - WAAS-SSRF-001: Cloud Metadata & Loopback SSRF (169.254.169.254, fd00:ec2::254, metadata.google.internal, 127.0.0.1)
   - WAAS-CMDI-001: OS Command Injection & Log4Shell (; cat /etc/passwd, | id, ${jndi:ldap://)
   - WAAS-PATH-001: Path Traversal (../, ..\, %2e%2e%2f, /etc/passwd)
   - WAAS-BOLA-001: Cross-tenant Object ID manipulation (API1)
   - WAAS-BOPLA-001: Mass Assignment undeclared body fields (is_admin, role, permissions) (API3)
   - WAAS-BFLA-001: Non-admin role calling administrative endpoints (API5).
3. **JWT & Rate-Limit Inspector**: Detect alg: none JWT headers, expired tokens, and IP request bursts exceeding rate_limit_rpm (WAAS-API4-RATELIMIT).
4. **Interactive Payload Replay Tester**: Test custom HTTP method/URI/headers/body payloads directly in the CLI, MCP, and Web Workbench.
5. **Multi-Format Virtual Patch Generator**: Generate Cloudflare Wirefilter, AWS WAFv2 JSON, ModSecurity SecRule, and Envoy HTTP Filter rules.

### App 07: ThreatSecure (Mirrors Cortex CDR / GuardDuty)
1. **Multi-Cloud & K8s Audit Log Normalizer**: Ingest AWS CloudTrail, GCP Audit Logs, Azure Activity Logs, and Kubernetes Audit Events.
2. **18-Rule MITRE ATT&CK for Cloud Detection Engine**:
   - T1562.008 Disable Cloud Logs (StopLogging, DeleteTrail, DeleteFlowLogs, DeleteDetector)
   - T1078.004 Root/IAM ConsoleLogin without MFA or from Tor/suspicious IP
   - T1098.001 Persistence via CreateAccessKey / CreateLoginProfile
   - T1098.003 Privilege Escalation via AttachUserPolicy / AttachRolePolicy / PutUserPolicy (AdministratorAccess)
   - T1496 Resource Hijacking via GPU instance launch (p3., p4., g5.)
   - T1555.006 Cloud Secrets Harvesting (GetSecretValue, GetParameter burst)
   - T1537 Data Exfiltration via Public EBS/RDS Snapshot Share (ModifySnapshotAttribute, ModifyDBSnapshotAttribute)
   - T1530 S3 Data Staged/Exfiltrated or Public Bucket Policy attached (PutBucketPolicy, PutBucketAcl)
   - T1485 Data Destruction (ScheduleKeyDeletion, DeleteBucket, DeleteDBInstance)
   - T1609 Container Administration Execution (pods/exec, ecs:ExecuteCommand, ssm:SendCommand).
3. **Kill-Chain Storyline Correlator**: Group detections by actor principal/IP across multiple MITRE tactics, computing confidence scores and escalating multi-tactic sequences to CRITICAL_INCIDENT_ACTIVE.
4. **RQL event from cloud.audit_logs Threat Hunting**: Filter events and detections by operation, principal, source IP, or MITRE tactic.
5. **Automated Containment Playbook Generator**: Emit step-by-step AWS CLI / kubectl containment commands per incident.

### App 08: GraphSecure (Mirrors Prisma Cloud Attack Path Engine)
1. **Multi-Cloud Exposure Graph Engine**: Model Internet, LoadBalancer, ComputeInstance, Container, IamRole, Database, DataStore, and KmsKey nodes connected by NetworkIngress, ExploitsVulnerability, AssumesRole, PermissionsGrant, LateralMove, and ReadsDataStore edges.
2. **Weighted Shortest Breach Path & Toxic Combination Solver**: Find all simple paths from is_internet_exposed entry nodes to is_crown_jewel targets, ranked by cumulative risk score and hop count.
3. **Built-in Toxic Combination Templates**: Filter paths by preset patterns (Internet -> CVE Workload -> Crown Jewel, Container Escape -> IAM Admin, Cross-Account Role -> Sensitive Data).
4. **Betweenness-Centrality Choke-Point Optimizer**: Rank edges by paths_severed_count and roi_percentage (% of total crown-jewel breach paths eliminated by fixing a single edge).
5. **Interactive What-If Edge Suppression Simulator**: Toggle any edge active/inactive in the engine and GUI workbench to immediately recompute surviving breach paths and verify remediation efficacy.

### App 09: NetSecure (Mirrors Prisma Cloud CNS / Aporeto)
1. **Bitwise IPv4 CIDR & Port-Range Symbolic Reachability Solver**: Parse CIDR blocks (a.b.c.d/prefix) into (u32, u32) network/mask pairs to prove whether traffic from src_ip to dst_ip:dst_port (TCP/UDP) is permitted or blocked by Security Group rules.
2. **VPC Flow Log Anomaly & Exposure Detector**:
   - CNS-NET-001: Cleartext sensitive protocols (HTTP:80, FTP:21, Telnet:23, LDAP:389)
   - CNS-NET-002: Public Internet ingress to sensitive management/DB ports (22, 3389, 3306, 5432, 6379, 27017, 9200)
   - CNS-NET-003: Potential data exfiltration (>100 MB outbound to public IP)
   - CNS-NET-004: Cross-subnet East-West lateral probe (REJECT burst or DMZ-to-DB direct flow).
3. **Security Group & NACL Exposure Auditor**: Flag 0.0.0.0/0 or ::/0 ingress to administrative/database ports (CNS-SG-001) and all-ports wildcard rules (CNS-SG-002).
4. **East-West Service Traffic Matrix**: Summarize observed src_addr -> dst_addr : dst_port flows vs. permitted security group policy.
5. **Zero-Trust Microsegmentation Policy Synthesizer**: Generate default-deny + observed-allow Kubernetes NetworkPolicy YAML (both Ingress and Egress) and AWS CLI revoke-security-group-ingress commands.

### App 10: AiSecure (Mirrors Prisma Cloud AI-SPM)
1. **AI-BOM & Shadow AI Inventory Auditor**: Audit ModelEndpoint, VectorDatabase, ModelWeightsStorage, and AgentExecutionEnvironment assets for unapproved Shadow AI (AI-SPM-001), public endpoints (AI-SPM-002), unencrypted model weights (AI-SPM-003), and unisolated RAG vector stores (AI-SPM-004).
2. **Model Artifact Pickle Opcode vs. SafeTensors Scanner**: Scan model artifact metadata/buffers for dangerous Python pickle deserialization opcodes (REDUCE, GLOBAL, STACK_GLOBAL, os.system, subprocess) (AI-SPM-006) vs. verified safetensors / GGUF formats.
3. **Autonomous Agent Excessive Agency Auditor (OWASP LLM08)**: Flag agent tools that can execute code or mutate data without requires_human_approval: true (AI-SPM-005).
4. **Interactive Prompt Injection, System-Prompt Extraction & PII Firewall (OWASP LLM01 / LLM06 / LLM07)**: Live inspection of prompt payloads for jailbreaks, system override directives, delimiter bypasses, and leaked credentials/SSNs/API keys.
5. **Guardrail Configuration Generator**: Synthesize Cloudflare AI Gateway JSON, AWS Bedrock Guardrail configs, and NeMo Guardrail input/output rules.

### App 11: SupplySecure (Mirrors Prisma CI/CD & Supply Chain Security)
1. **CI/CD Workflow Security Scanner**: Scan GitHub Actions / GitLab CI workflow definitions for unpinned actions (SUPPLY-CI-001), pull_request_target untrusted checkout (SUPPLY-CI-002), script injection ${{ github.event... }} (SUPPLY-CI-003), and overpermissive GITHUB_TOKEN permissions (SUPPLY-CI-004).
2. **SLSA v1.0 Provenance & Level 0-3 Evaluator**: Verify SlsaProvenance attestations for hermeticity, isolated build environment, trusted builder ID, 40-char commit SHA, and dependency digests (SUPPLY-SLSA-001).
3. **Sigstore / Cosign Signature & Rekor Verifier**: Flag unsigned container images (SUPPLY-COSIGN-001) and signed artifacts missing Rekor transparency log entries (SUPPLY-COSIGN-002).
4. **Dependency Confusion & Levenshtein Typosquatting Detector**: Flag private-scope packages resolvable on public registries (SUPPLY-DEP-001) and packages within Levenshtein edit distance d <= 2 of popular packages (SUPPLY-DEP-002).
5. **Kyverno Admission Policy & Auto-Pinned Workflow Generator**: Generate Kubernetes Kyverno signature-enforcement ClusterPolicy YAML and SHA-pinned GitHub Actions workflow patches.

### App 12: PolicySecure (Mirrors Prisma RQL Studio & Policy IDE)
1. **Full-Grammar RQL Parser & Evaluator**: Support all 6 RQL families (config, iam, event, data, network, ai) with boolean and/or/not, in (...), numeric comparisons, and array paths.
2. **Live RQL AST Explain-Plan Profiler**: Output parse latency in microseconds, AST node hierarchy, estimated cost, validation errors, and context-sensitive autocomplete tokens.
3. **Policy-as-Code Rule & Pack Validator**: Validate custom PolicyPack definitions for valid RQL syntax, non-empty compliance control mappings, and remediation templates.
4. **Embedded Positive & Negative Fixture Test Runner**: Execute pass_fixtures and fail_fixtures against each rule's RQL query and report pass/fail assertions with sub-millisecond timing.
5. **Signed Policy Pack Exporter**: Export verified .csec-policy.json bundles with deterministic state_hash digests.

### App 13: ComplianceSecure (Mirrors Prisma Compliance Command Center)
1. **12-Module Unified Posture Aggregator**: Ingest findings across all 12 CloudSecure security engines into a deduplicated risk ledger.
2. **6-Framework Continuous Readiness Engine**: Compute control-by-control pass/fail status and readiness percentages for SOC 2 Type II, ISO/IEC 27001:2022, PCI-DSS v4.0, HIPAA Security Rule, NIST CSF 2.0, and FedRAMP Moderate.
3. **Cross-Framework Control Crosswalk**: Show all compliance controls across all 6 frameworks satisfied by each technical finding.
4. **Interactive Top-10 Breach-Stopping Remediation Queue**: Rank remediations by blast-radius reduction score and allow interactive completion toggling to simulate live readiness score improvements.
5. **Cryptographically Signed Audit Evidence Bundle Exporter**: Export auditor-ready packages in Markdown, JSON, CSV, and SARIF 2.1.0 sealed with a manifest_sha256 hash.
