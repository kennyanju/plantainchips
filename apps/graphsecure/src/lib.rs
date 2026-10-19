use chrono::Utc;
use cloudsecure_automation::{CloudSecureAppEngine, CommandReceipt};
use cloudsecure_types::{
    AppCatalogEntry, CloudProvider, Evidence, Finding, FindingStatus, RemediationFormat,
    RemediationPatch, SarifArtifactLocation, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GraphError {
    #[error("Failed to parse graph JSON: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Node not found in graph: '{0}'")]
    NodeNotFound(String),
    #[error("Edge not found in graph: '{0}'")]
    EdgeNotFound(String),
}

/// Category of security graph entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeType {
    Internet,
    LoadBalancer,
    ComputeInstance,
    Container,
    IamRole,
    Database,
    DataStore,
    KmsKey,
}

/// Relationship or transition vector connecting graph entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeType {
    NetworkIngress,
    ExploitsVulnerability,
    AssumesRole,
    PermissionsGrant,
    LateralMove,
    ReadsDataStore,
}

/// Security graph node representing an asset, identity, or perimeter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub name: String,
    pub node_type: NodeType,
    pub provider: CloudProvider,
    pub is_internet_exposed: bool,
    pub is_crown_jewel: bool,
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub misconfigurations: Vec<String>,
}

/// Directional security relationship or exploit transition edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub edge_type: EdgeType,
    pub risk_weight: f32,
    #[serde(default = "default_true")]
    pub is_active: bool,
    pub remediation_action: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Multi-hop breach path leading from internet exposure to a crown jewel asset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub title: String,
    pub hops: Vec<String>,
    pub edges: Vec<String>,
    pub cumulative_risk_score: f32,
    pub severity: Severity,
    pub description: String,
}

/// High-leverage choke point remediation that severs multiple attack paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChokePoint {
    pub edge_id: String,
    pub source_node: String,
    pub target_node: String,
    pub paths_severed_count: usize,
    pub roi_percentage: f32,
    pub remediation_hcl: String,
}

/// Attack path and exposure graph data structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl SecurityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: GraphNode) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: GraphEdge) {
        self.edges.push(edge);
    }

    pub fn state_hash(&self) -> String {
        let serialized = serde_json::to_string(self).unwrap_or_default();
        format!("{:x}", Sha256::digest(serialized.as_bytes()))
    }
}

/// Core graph traversal and toxic combination solver.
pub struct ToxicCombinationSolver;

impl ToxicCombinationSolver {
    /// Discovers all active attack paths from any internet-exposed asset to crown jewels.
    pub fn find_paths(graph: &SecurityGraph) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let node_map: HashMap<&str, &GraphNode> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

        // Adjacency list for active edges
        let mut adj: HashMap<&str, Vec<(&str, &str, f32)>> = HashMap::new();
        for edge in &graph.edges {
            if edge.is_active {
                adj.entry(&edge.source)
                    .or_default()
                    .push((&edge.target, &edge.id, edge.risk_weight));
            }
        }

        let entry_points: Vec<&GraphNode> = graph
            .nodes
            .iter()
            .filter(|n| n.is_internet_exposed || n.node_type == NodeType::Internet)
            .collect();

        for entry in entry_points {
            let mut queue: VecDeque<(Vec<String>, Vec<String>, f32)> = VecDeque::new();
            queue.push_back((vec![entry.id.clone()], Vec::new(), 1.0));

            while let Some((curr_hops, curr_edges, risk)) = queue.pop_front() {
                let last_node_id = curr_hops.last().unwrap();
                let last_node = match node_map.get(last_node_id.as_str()) {
                    Some(n) => *n,
                    None => continue,
                };

                // Check if target is a Crown Jewel
                if last_node.is_crown_jewel && curr_hops.len() > 1 {
                    let path_id = format!("PATH-{}", paths.len() + 1);
                    let title = format!(
                        "Toxic Path: {} -> {} ({} hops)",
                        entry.name,
                        last_node.name,
                        curr_hops.len()
                    );
                    let sev = if risk >= 3.0 || !last_node.cves.is_empty() {
                        Severity::Critical
                    } else {
                        Severity::High
                    };

                    paths.push(AttackPath {
                        id: path_id,
                        title,
                        hops: curr_hops.clone(),
                        edges: curr_edges.clone(),
                        cumulative_risk_score: risk,
                        severity: sev,
                        description: format!(
                            "Exploit chain traversing {} to compromise crown jewel asset '{}'.",
                            curr_hops.join(" -> "),
                            last_node.name
                        ),
                    });
                    continue;
                }

                if curr_hops.len() > 8 {
                    // Limit hop depth to avoid infinite cycles
                    continue;
                }

                if let Some(neighbors) = adj.get(last_node_id.as_str()) {
                    for (next_id, edge_id, weight) in neighbors {
                        if !curr_hops.contains(&next_id.to_string()) {
                            let mut next_hops = curr_hops.clone();
                            next_hops.push(next_id.to_string());
                            let mut next_edges = curr_edges.clone();
                            next_edges.push(edge_id.to_string());

                            let node_risk = match node_map.get(*next_id) {
                                Some(n) => (n.cves.len() as f32 * 1.5) + (n.misconfigurations.len() as f32 * 1.0),
                                None => 0.0,
                            };

                            queue.push_back((next_hops, next_edges, risk + weight + node_risk));
                        }
                    }
                }
            }
        }

        paths
    }
}

/// Choke point optimizer computing edge betweenness across all attack paths.
pub struct ChokePointOptimizer;

impl ChokePointOptimizer {
    pub fn compute_choke_points(graph: &SecurityGraph, paths: &[AttackPath]) -> Vec<ChokePoint> {
        if paths.is_empty() {
            return Vec::new();
        }

        let total_paths = paths.len();
        let mut edge_counts: HashMap<String, usize> = HashMap::new();

        for p in paths {
            let mut seen_in_path = HashSet::new();
            for e in &p.edges {
                if seen_in_path.insert(e.clone()) {
                    *edge_counts.entry(e.clone()).or_insert(0) += 1;
                }
            }
        }

        let mut choke_points = Vec::new();
        let edge_map: HashMap<&str, &GraphEdge> = graph.edges.iter().map(|e| (e.id.as_str(), e)).collect();

        for (edge_id, count) in edge_counts {
            if let Some(edge) = edge_map.get(edge_id.as_str()) {
                let roi = (count as f32 / total_paths as f32) * 100.0;
                let hcl = edge.remediation_action.clone().unwrap_or_else(|| {
                    format!(
                        r#"# Choke point remediation for edge {}
resource "aws_security_group_rule" "revoke_{}" {{
  type        = "ingress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = []
}}"#,
                        edge.id, edge.id
                    )
                });

                choke_points.push(ChokePoint {
                    edge_id: edge.id.clone(),
                    source_node: edge.source.clone(),
                    target_node: edge.target.clone(),
                    paths_severed_count: count,
                    roi_percentage: roi,
                    remediation_hcl: hcl,
                });
            }
        }

        choke_points.sort_by(|a, b| b.paths_severed_count.cmp(&a.paths_severed_count));
        choke_points
    }
}

/// Commands accepted by GraphSecure engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraphCommand {
    LoadGraph(String),
    ToggleEdge { edge_id: String, active: bool },
    ResetSimulation,
}

/// State snapshot for GraphSecure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStateSnapshot {
    pub graph: SecurityGraph,
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
}

/// Main domain engine for GraphSecure (App 08).
#[derive(Debug, Clone, Default)]
pub struct GraphEngine {
    pub graph: SecurityGraph,
    pub paths: Vec<AttackPath>,
    pub choke_points: Vec<ChokePoint>,
    pub findings: Vec<Finding>,
}

impl GraphEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn recompute(&mut self) {
        self.paths = ToxicCombinationSolver::find_paths(&self.graph);
        self.choke_points = ChokePointOptimizer::compute_choke_points(&self.graph, &self.paths);
        self.sync_findings();
    }

    fn sync_findings(&mut self) {
        self.findings.clear();
        for p in &self.paths {
            let evidence = Evidence {
                rule_id: "GRAPH-TOXIC-001".into(),
                target_path: p.hops.join(" -> "),
                expected_value: "Zero viable breach paths to crown jewels".into(),
                observed_value: format!("Active attack path with {} hops", p.hops.len()),
                message: p.description.clone(),
                resource_state_hash: self.graph.state_hash(),
            };

            let rem_hcl = if let Some(cp) = self.choke_points.first() {
                cp.remediation_hcl.clone()
            } else {
                "# Remediate perimeter exposure".into()
            };

            self.findings.push(Finding {
                id: format!("GRAPH-{}", p.id),
                rule_id: "GRAPH-TOXIC-001".into(),
                title: p.title.clone(),
                severity: p.severity,
                status: FindingStatus::Fail,
                provider: CloudProvider::Aws,
                account_id: "multi-cloud".into(),
                region: "global".into(),
                resource_id: p.hops.last().cloned().unwrap_or_default(),
                resource_arn: format!("arn:cloudsecure:graph:path:{}", p.id),
                resource_type: "AttackPath".into(),
                framework_mappings: vec!["MITRE ATT&CK: Enterprise".into(), "CIS Benchmark".into()],
                evidence,
                remediation: Some(RemediationPatch {
                    format: RemediationFormat::TerraformHcl,
                    code: rem_hcl.clone(),
                    sha256_hash: format!("{:x}", Sha256::digest(rem_hcl.as_bytes())),
                }),
                timestamp: Utc::now(),
            });
        }
    }
}

impl CloudSecureAppEngine for GraphEngine {
    type Command = GraphCommand;
    type StateSnapshot = GraphStateSnapshot;
    type Error = GraphError;

    fn app_metadata(&self) -> AppCatalogEntry {
        AppCatalogEntry {
            index: 8,
            id: "graphsecure",
            name: "GraphSecure",
            pillar: "POSTURE",
            version: "0.1.0",
            license: "MIT OR Apache-2.0",
            description: "Multi-cloud attack path simulator and choke point optimizer calculating shortest traversals to crown jewels.",
        }
    }

    fn execute(&mut self, cmd: Self::Command) -> Result<CommandReceipt, Self::Error> {
        let start = std::time::Instant::now();
        match cmd {
            GraphCommand::LoadGraph(json_str) => {
                self.graph = serde_json::from_str(&json_str)?;
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "LoadGraph".into(),
                    records_affected: self.graph.nodes.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: self.graph.state_hash(),
                })
            }
            GraphCommand::ToggleEdge { edge_id, active } => {
                let mut found = false;
                for edge in &mut self.graph.edges {
                    if edge.id.eq_ignore_ascii_case(&edge_id) {
                        edge.is_active = active;
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Err(GraphError::EdgeNotFound(edge_id));
                }
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "ToggleEdge".into(),
                    records_affected: 1,
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: format!("{}:{}", edge_id, active),
                })
            }
            GraphCommand::ResetSimulation => {
                for edge in &mut self.graph.edges {
                    edge.is_active = true;
                }
                self.recompute();
                Ok(CommandReceipt {
                    command_name: "ResetSimulation".into(),
                    records_affected: self.graph.edges.len(),
                    execution_ms: start.elapsed().as_millis() as u64,
                    state_hash: "reset".into(),
                })
            }
        }
    }

    fn snapshot(&self) -> Self::StateSnapshot {
        GraphStateSnapshot {
            graph: self.graph.clone(),
            paths: self.paths.clone(),
            choke_points: self.choke_points.clone(),
        }
    }

    fn export_sarif(&self) -> SarifReport {
        let mut rules = Vec::new();
        let mut results = Vec::new();

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
                        name: "GraphSecure".into(),
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
