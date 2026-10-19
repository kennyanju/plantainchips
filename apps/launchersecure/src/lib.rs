pub mod updater;

use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, Finding, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use updater::{PackageArtifact, RollbackRecord, UpdaterError, UpdaterManager};

#[derive(Error, Debug)]
pub enum LauncherError {
    #[error("Unknown application ID '{0}'")]
    UnknownApp(String),
    #[error("Updater error: {0}")]
    Updater(#[from] UpdaterError),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Catalog visualization mode matching storytold/craft-launcher HUD toggle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogViewMode {
    Grid,
    Table,
}

/// Application installation and lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppStatus {
    NotInstalled,
    Installed,
    UpdateAvailable,
    Quarantined,
}

/// Workspace interface theme mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    Light,
    Dark,
    System,
}

/// Detailed catalog representation for each CloudSecure suite member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteAppItem {
    pub index: usize,
    pub id: String,
    pub name: String,
    pub pillar: String,
    pub description: String,
    pub accent_color: String,
    pub icon_mark: String,
    pub installed_version: Option<String>,
    pub latest_version: String,
    pub release_date: String,
    pub download_size_mb: u32,
    pub sha256_digest: String,
    pub status: AppStatus,
    pub is_running: bool,
}

/// In-memory state snapshot of LauncherSecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LauncherStateSnapshot {
    pub view_mode: CatalogViewMode,
    pub pillar_filter: String,
    pub search_query: String,
    pub theme: ThemeMode,
    pub locale: String,
    pub platform: String,
    pub apps: Vec<SuiteAppItem>,
    pub rollback_points: Vec<RollbackRecord>,
}

/// Executable commands driving the unified LauncherSecure engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LauncherCommand {
    SetViewMode(CatalogViewMode),
    SetPillarFilter(String),
    SetSearchQuery(String),
    SetTheme(ThemeMode),
    SetLocale(String),
    InstallApp {
        app_id: String,
        version: String,
        payload_bytes: Vec<u8>,
        expected_sha256: String,
    },
    RollbackApp(String),
    CheckAllUpdates,
}

/// Complete LauncherSecure domain engine.
#[derive(Debug, Clone)]
pub struct LauncherEngine {
    pub view_mode: CatalogViewMode,
    pub pillar_filter: String,
    pub search_query: String,
    pub theme: ThemeMode,
    pub locale: String,
    pub platform: String,
    pub apps: Vec<SuiteAppItem>,
    pub updater: UpdaterManager,
    pub findings: Vec<Finding>,
}

impl Default for LauncherEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LauncherEngine {
    pub fn new() -> Self {
        let detected_platform = detect_current_platform();
        Self {
            view_mode: CatalogViewMode::Grid,
            pillar_filter: "ALL".into(),
            search_query: String::new(),
            theme: ThemeMode::Dark,
            locale: "en".into(),
            platform: detected_platform,
            apps: standard_cloudsecure_catalog(),
            updater: UpdaterManager::new(),
            findings: Vec::new(),
        }
    }

    /// Returns filtered apps based on search query and active CNAPP pillar.
    pub fn filtered_apps(&self) -> Vec<&SuiteAppItem> {
        self.apps
            .iter()
            .filter(|app| {
                let matches_pillar = if self.pillar_filter.eq_ignore_ascii_case("ALL") {
                    true
                } else {
                    app.pillar.eq_ignore_ascii_case(&self.pillar_filter)
                };

                let matches_query = if self.search_query.trim().is_empty() {
                    true
                } else {
                    let q = self.search_query.to_lowercase();
                    app.name.to_lowercase().contains(&q)
                        || app.description.to_lowercase().contains(&q)
                        || app.id.to_lowercase().contains(&q)
                };

                matches_pillar && matches_query
            })
            .collect()
    }
}

impl CloudSecureAppEngine for LauncherEngine {
    type Command = LauncherCommand;
    type StateSnapshot = LauncherStateSnapshot;
    type Error = LauncherError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 0,
            id: "launchersecure",
            name: "LauncherSecure",
            pillar: "GOVERNANCE",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Unified CloudSecure application launcher, workspace manager, and cryptographically verified auto-updater.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            LauncherCommand::SetViewMode(mode) => {
                self.view_mode = mode;
                Ok(CommandReceipt {
                    command_name: "SetViewMode".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:?}", mode),
                })
            }
            LauncherCommand::SetPillarFilter(pillar) => {
                self.pillar_filter = pillar;
                Ok(CommandReceipt {
                    command_name: "SetPillarFilter".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: self.pillar_filter.clone(),
                })
            }
            LauncherCommand::SetSearchQuery(q) => {
                self.search_query = q;
                Ok(CommandReceipt {
                    command_name: "SetSearchQuery".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: self.search_query.clone(),
                })
            }
            LauncherCommand::SetTheme(theme) => {
                self.theme = theme;
                Ok(CommandReceipt {
                    command_name: "SetTheme".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{:?}", theme),
                })
            }
            LauncherCommand::SetLocale(loc) => {
                self.locale = loc;
                Ok(CommandReceipt {
                    command_name: "SetLocale".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: self.locale.clone(),
                })
            }
            LauncherCommand::InstallApp {
                app_id,
                version,
                payload_bytes,
                expected_sha256,
            } => {
                let app = self
                    .apps
                    .iter_mut()
                    .find(|a| a.id.eq_ignore_ascii_case(&app_id))
                    .ok_or_else(|| LauncherError::UnknownApp(app_id.clone()))?;

                let prev_ver = app.installed_version.as_deref();
                match self.updater.install_or_update(
                    &app_id,
                    &version,
                    &payload_bytes,
                    &expected_sha256,
                    prev_ver,
                ) {
                    Ok(verified_hash) => {
                        app.installed_version = Some(version);
                        app.status = AppStatus::Installed;
                        app.sha256_digest = verified_hash.clone();
                        Ok(CommandReceipt {
                            command_name: "InstallApp".into(),
                            records_affected: 1,
                            execution_ms: start.elapsed().as_millis() as u64,
                            state_hash: verified_hash,
                        })
                    }
                    Err(e) => {
                        app.status = AppStatus::Quarantined;
                        Err(LauncherError::Updater(e))
                    }
                }
            }
            LauncherCommand::RollbackApp(app_id) => {
                let record = self.updater.rollback(&app_id)?;
                let app = self
                    .apps
                    .iter_mut()
                    .find(|a| a.id.eq_ignore_ascii_case(&app_id))
                    .ok_or_else(|| LauncherError::UnknownApp(app_id.clone()))?;

                app.installed_version = Some(record.previous_version.clone());
                app.status = AppStatus::Installed;
                app.sha256_digest = record.previous_sha256;

                Ok(CommandReceipt {
                    command_name: "RollbackApp".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: record.previous_version,
                })
            }
            LauncherCommand::CheckAllUpdates => {
                let mut updates = 0;
                for a in &mut self.apps {
                    if let Some(ref inst) = a.installed_version {
                        if inst != &a.latest_version {
                            a.status = AppStatus::UpdateAvailable;
                            updates += 1;
                        }
                    }
                }
                Ok(CommandReceipt {
                    command_name: "CheckAllUpdates".into(),
                    records_affected: updates,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("updates-{}", updates),
                })
            }
        }
    }

    fn snapshot(&self) -> Self::StateSnapshot {
        LauncherStateSnapshot {
            view_mode: self.view_mode,
            pillar_filter: self.pillar_filter.clone(),
            search_query: self.search_query.clone(),
            theme: self.theme,
            locale: self.locale.clone(),
            platform: self.platform.clone(),
            apps: self.apps.clone(),
            rollback_points: self.updater.rollbacks.values().cloned().collect(),
        }
    }

    fn export_sarif(&self) -> SarifReport {
        let mut results = Vec::new();
        let mut rules = Vec::new();

        for f in &self.findings {
            rules.push(SarifRule {
                id: f.rule_id.clone(),
                name: f.title.clone(),
                short_description: SarifMessage {
                    text: f.evidence.message.clone(),
                },
            });

            results.push(SarifResult {
                rule_id: f.rule_id.clone(),
                level: "error".into(),
                message: SarifMessage {
                    text: format!("{}: {}", f.title, f.evidence.message),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.resource_arn.clone(),
                        },
                    },
                }],
            });
        }

        SarifReport {
            schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".into(),
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "LauncherSecure".into(),
                        version: "0.1.0".into(),
                        information_uri: "https://github.com/kennyanju/plantainchips".into(),
                        rules,
                    },
                },
                results,
            }],
        }
    }
}

/// Detects host operating system and CPU architecture.
pub fn detect_current_platform() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!("{}-{}", os, arch)
}

/// Canonical catalog containing all 14 applications in the CloudSecure suite.
pub fn standard_cloudsecure_catalog() -> Vec<SuiteAppItem> {
    vec![
        SuiteAppItem {
            index: 0,
            id: "launchersecure".into(),
            name: "LauncherSecure".into(),
            pillar: "GOVERNANCE".into(),
            description: "Unified suite launcher, workspace manager, and cryptographically verified auto-updater.".into(),
            accent_color: "#3B82F6".into(),
            icon_mark: "RocketCompass".into(),
            installed_version: Some("0.1.0".into()),
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 18,
            sha256_digest: "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".into(),
            status: AppStatus::Installed,
            is_running: true,
        },
        SuiteAppItem {
            index: 1,
            id: "posturesecure".into(),
            name: "PostureSecure".into(),
            pillar: "POSTURE".into(),
            description: "Multi-cloud CSPM with RQL engine, CIS 3.0 benchmarks, and Terraform remediation.".into(),
            accent_color: "#0F52BA".into(),
            icon_mark: "ShieldGrid".into(),
            installed_version: Some("0.1.0".into()),
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 24,
            sha256_digest: "646da62a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6".into(),
            status: AppStatus::Installed,
            is_running: false,
        },
        SuiteAppItem {
            index: 2,
            id: "datasecure".into(),
            name: "DataSecure".into(),
            pillar: "DATA".into(),
            description: "Data Security Posture Management (DSPM) and DDR engine classifying sensitive PII, PCI, and keys.".into(),
            accent_color: "#0D6E52".into(),
            icon_mark: "VaultCylinder".into(),
            installed_version: Some("0.1.0".into()),
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 22,
            sha256_digest: "ee66c7a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d".into(),
            status: AppStatus::Installed,
            is_running: false,
        },
        SuiteAppItem {
            index: 3,
            id: "workloadsecure".into(),
            name: "WorkloadSecure".into(),
            pillar: "WORKLOAD".into(),
            description: "CWPP container image layer analyzer, CVE matcher, and runtime profile generator.".into(),
            accent_color: "#8B3A0E".into(),
            icon_mark: "PodMatrix".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 28,
            sha256_digest: "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 4,
            id: "identitysecure".into(),
            name: "IdentitySecure".into(),
            pillar: "IDENTITY".into(),
            description: "CIEM net-effective permissions solver, privilege escalation detector, and blast radius engine.".into(),
            accent_color: "#6B21A8".into(),
            icon_mark: "KeyGraph".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 21,
            sha256_digest: "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 5,
            id: "codesecure".into(),
            name: "CodeSecure".into(),
            pillar: "CODE".into(),
            description: "ASPM and Infrastructure as Code (IaC) static analyzer for Terraform, CloudFormation, and Dockerfiles.".into(),
            accent_color: "#C2410C".into(),
            icon_mark: "CodeBrackets".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 26,
            sha256_digest: "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 6,
            id: "waassecure".into(),
            name: "WaasSecure".into(),
            pillar: "NETWORK".into(),
            description: "Web-App and API Security policy compiler with OWASP Top 10 rules and OpenAPI contract validation.".into(),
            accent_color: "#B45309".into(),
            icon_mark: "GlobeFirewall".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 19,
            sha256_digest: "a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 7,
            id: "threatsecure".into(),
            name: "ThreatSecure".into(),
            pillar: "RUNTIME".into(),
            description: "Cloud Detection and Response (CDR) engine evaluating audit event streams against MITRE ATT&CK.".into(),
            accent_color: "#BE123C".into(),
            icon_mark: "RadarPing".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 25,
            sha256_digest: "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 8,
            id: "graphsecure".into(),
            name: "GraphSecure".into(),
            pillar: "POSTURE".into(),
            description: "Multi-cloud attack path engine computing shortest traversal from Internet exposure to critical assets.".into(),
            accent_color: "#4338CA".into(),
            icon_mark: "AttackGraph".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 31,
            sha256_digest: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 9,
            id: "netsecure".into(),
            name: "NetSecure".into(),
            pillar: "NETWORK".into(),
            description: "Cloud Network Security (CNS) analyzer verifying security group rules and zero-trust microsegmentation.".into(),
            accent_color: "#0369A1".into(),
            icon_mark: "NetworkNodes".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 20,
            sha256_digest: "d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 10,
            id: "aisecure".into(),
            name: "AiSecure".into(),
            pillar: "GOVERNANCE".into(),
            description: "AI-SPM security engine auditing LLM model artifacts, prompt injection defenses, and pipeline egress.".into(),
            accent_color: "#7E22CE".into(),
            icon_mark: "NeuralShield".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 23,
            sha256_digest: "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 11,
            id: "supplysecure".into(),
            name: "SupplySecure".into(),
            pillar: "CODE".into(),
            description: "Software supply chain security scanner auditing SBOMs (CycloneDX/SPDX) and build pipeline integrity.".into(),
            accent_color: "#0F766E".into(),
            icon_mark: "SupplyChain".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 22,
            sha256_digest: "f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 12,
            id: "policysecure".into(),
            name: "PolicySecure".into(),
            pillar: "GOVERNANCE".into(),
            description: "RQL studio, grammar debugger, and custom security policy authoring environment.".into(),
            accent_color: "#1D4ED8".into(),
            icon_mark: "ScaleBalance".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 17,
            sha256_digest: "a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
        SuiteAppItem {
            index: 13,
            id: "compliancesecure".into(),
            name: "ComplianceSecure".into(),
            pillar: "GOVERNANCE".into(),
            description: "Executive compliance auditor, audit bundle generator, and gap analysis for SOC 2, ISO 27001, and PCI-DSS.".into(),
            accent_color: "#475569".into(),
            icon_mark: "CertificateRibbon".into(),
            installed_version: None,
            latest_version: "0.1.0".into(),
            release_date: "2026-10-19".into(),
            download_size_mb: 24,
            sha256_digest: "b2c4d6e8f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4".into(),
            status: AppStatus::NotInstalled,
            is_running: false,
        },
    ]
}
