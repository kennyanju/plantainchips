use cloudsecure_types::CloudResource;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum RqlError {
    #[error("Parse error at position {0}: {1}")]
    ParseError(usize, String),
    #[error("Unsupported resource family: {0}")]
    UnsupportedFamily(String),
    #[error("Invalid comparison operator: {0}")]
    InvalidOperator(String),
}

/// Resource family targeted by the RQL statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceFamily {
    Config,
    Iam,
    Event,
    Data,
    Network,
    Ai,
}

/// Comparison operations supported within RQL filter clauses.
#[derive(Debug, Clone, PartialEq)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    Contains,
    IsTrue,
    IsFalse,
}

/// Individual AST predicate condition in a WHERE clause.
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    CloudType(String),
    ApiName(String),
    Region(String),
    AccountId(String),
    JsonRule {
        path: Vec<String>,
        op: ComparisonOp,
        target_value: Option<String>,
    },
    RawExpression(String),
}

/// Parsed RQL Abstract Syntax Tree representation.
#[derive(Debug, Clone, PartialEq)]
pub struct RqlQuery {
    pub family: ResourceFamily,
    pub target: String,
    pub predicates: Vec<Predicate>,
}

impl RqlQuery {
    /// Parses a standard RQL statement into an executable AST query plan.
    pub fn parse(input: &str) -> Result<Self, RqlError> {
        let trimmed = input.trim();
        let lower = trimmed.to_lowercase();

        let family = if lower.starts_with("config from") {
            ResourceFamily::Config
        } else if lower.starts_with("iam from") {
            ResourceFamily::Iam
        } else if lower.starts_with("event from") {
            ResourceFamily::Event
        } else if lower.starts_with("data from") {
            ResourceFamily::Data
        } else if lower.starts_with("network from") {
            ResourceFamily::Network
        } else if lower.starts_with("ai from") {
            ResourceFamily::Ai
        } else {
            return Err(RqlError::ParseError(0, "Statement must start with a valid RQL clause ('config from', 'iam from', 'event from', 'data from', 'network from', 'ai from')".into()));
        };

        let where_idx = lower.find(" where ");
        let (target, where_clause) = match where_idx {
            Some(idx) => {
                let from_end = lower.find("from").unwrap() + 4;
                let target_part = trimmed[from_end..idx].trim().to_string();
                let where_part = trimmed[idx + 7..].trim();
                (target_part, Some(where_part))
            }
            None => {
                let from_end = lower.find("from").unwrap() + 4;
                let target_part = trimmed[from_end..].trim().to_string();
                (target_part, None)
            }
        };

        let mut predicates = Vec::new();
        if let Some(clause) = where_clause {
            let terms = clause.split(" and ");
            for term in terms {
                let term_trimmed = term.trim();
                if term_trimmed.is_empty() {
                    continue;
                }

                let term_lower = term_trimmed.to_lowercase();
                if term_lower.starts_with("cloud.type") {
                    let val = extract_literal(term_trimmed);
                    predicates.push(Predicate::CloudType(val));
                } else if term_lower.starts_with("api.name") {
                    let val = extract_literal(term_trimmed);
                    predicates.push(Predicate::ApiName(val));
                } else if term_lower.starts_with("json.rule") {
                    let rule_expr = if let Some(eq_pos) = term_trimmed.find('=') {
                        term_trimmed[eq_pos + 1..].trim()
                    } else {
                        term_trimmed
                    };
                    let parsed_rule = parse_json_rule(rule_expr)?;
                    predicates.push(parsed_rule);
                } else {
                    predicates.push(Predicate::RawExpression(term_trimmed.to_string()));
                }
            }
        }

        Ok(RqlQuery {
            family,
            target,
            predicates,
        })
    }

    /// Evaluates whether an ingested cloud resource matches the query predicates.
    pub fn evaluate(&self, resource: &CloudResource) -> bool {
        for pred in &self.predicates {
            match pred {
                Predicate::CloudType(expected) => {
                    if resource.provider.to_string() != expected.to_lowercase() {
                        return false;
                    }
                }
                Predicate::ApiName(expected) => {
                    if !resource.resource_type.eq_ignore_ascii_case(expected)
                        && !resource.service.eq_ignore_ascii_case(expected)
                    {
                        return false;
                    }
                }
                Predicate::Region(expected) => {
                    if !resource.region.eq_ignore_ascii_case(expected) {
                        return false;
                    }
                }
                Predicate::AccountId(expected) => {
                    if resource.account_id != *expected {
                        return false;
                    }
                }
                Predicate::JsonRule {
                    path,
                    op,
                    target_value,
                } => {
                    let observed = resolve_json_path(&resource.state, path);
                    if !evaluate_json_match(observed, op, target_value.as_deref()) {
                        return false;
                    }
                }
                Predicate::RawExpression(expr) => {
                    // Fallback substring scan in serialized state
                    let serialized = serde_json::to_string(&resource.state).unwrap_or_default();
                    if !serialized.contains(expr) {
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn extract_literal(expr: &str) -> String {
    let mut quote_start = None;
    for (i, c) in expr.char_indices() {
        if c == '\'' || c == '"' {
            if let Some(start) = quote_start {
                return expr[start + 1..i].to_string();
            } else {
                quote_start = Some(i);
            }
        }
    }
    // Fallback: extract token after equals
    if let Some(pos) = expr.find('=') {
        expr[pos + 1..].trim().trim_matches('\'').trim_matches('"').to_string()
    } else {
        expr.trim().to_string()
    }
}

fn parse_json_rule(expr: &str) -> Result<Predicate, RqlError> {
    let lower = expr.to_lowercase();
    if lower.ends_with("is false") {
        let path_str = expr[..expr.len() - 8].trim();
        let path = path_str.split('.').map(|s| s.trim().to_string()).collect();
        return Ok(Predicate::JsonRule {
            path,
            op: ComparisonOp::IsFalse,
            target_value: None,
        });
    }

    if lower.ends_with("is true") {
        let path_str = expr[..expr.len() - 7].trim();
        let path = path_str.split('.').map(|s| s.trim().to_string()).collect();
        return Ok(Predicate::JsonRule {
            path,
            op: ComparisonOp::IsTrue,
            target_value: None,
        });
    }

    if let Some(pos) = expr.find(" contains ") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 10..]);
        let path = path_str.split('.').map(|s| s.trim().to_string()).collect();
        return Ok(Predicate::JsonRule {
            path,
            op: ComparisonOp::Contains,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find("!=") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 2..]);
        let path = path_str.split('.').map(|s| s.trim().to_string()).collect();
        return Ok(Predicate::JsonRule {
            path,
            op: ComparisonOp::NotEqual,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find('=') {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 1..]);
        let path = path_str.split('.').map(|s| s.trim().to_string()).collect();
        return Ok(Predicate::JsonRule {
            path,
            op: ComparisonOp::Equal,
            target_value: Some(val),
        });
    }

    Ok(Predicate::RawExpression(expr.to_string()))
}

fn resolve_json_path<'a>(root: &'a serde_json::Value, path: &[String]) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(segment)?;
            }
            serde_json::Value::Array(arr) => {
                // If segment is numeric index
                if let Ok(idx) = segment.parse::<usize>() {
                    current = arr.get(idx)?;
                } else {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(current)
}

fn evaluate_json_match(
    observed: Option<&serde_json::Value>,
    op: &ComparisonOp,
    target: Option<&str>,
) -> bool {
    match op {
        ComparisonOp::IsFalse => match observed {
            Some(serde_json::Value::Bool(b)) => !*b,
            Some(serde_json::Value::Null) | None => true,
            _ => false,
        },
        ComparisonOp::IsTrue => match observed {
            Some(serde_json::Value::Bool(b)) => *b,
            _ => false,
        },
        ComparisonOp::Equal => match (observed, target) {
            (Some(serde_json::Value::String(s)), Some(t)) => s.eq_ignore_ascii_case(t),
            (Some(serde_json::Value::Bool(b)), Some(t)) => b.to_string().eq_ignore_ascii_case(t),
            (Some(serde_json::Value::Number(n)), Some(t)) => n.to_string() == t,
            _ => false,
        },
        ComparisonOp::NotEqual => match (observed, target) {
            (Some(serde_json::Value::String(s)), Some(t)) => !s.eq_ignore_ascii_case(t),
            (Some(serde_json::Value::Bool(b)), Some(t)) => !b.to_string().eq_ignore_ascii_case(t),
            (Some(serde_json::Value::Number(n)), Some(t)) => n.to_string() != t,
            (None, _) => true,
            _ => true,
        },
        ComparisonOp::Contains => match (observed, target) {
            (Some(serde_json::Value::String(s)), Some(t)) => s.contains(t),
            (Some(serde_json::Value::Array(arr)), Some(t)) => arr.iter().any(|item| {
                if let serde_json::Value::String(s) = item {
                    s == t
                } else {
                    false
                }
            }),
            _ => false,
        },
    }
}
