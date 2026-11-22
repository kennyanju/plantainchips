pub use cloudsecure_types::CloudResource;
use thiserror::Error;

pub type Predicate = FieldPredicate;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceFamily {
    Config,
    Iam,
    Event,
    Data,
    Network,
    Ai,
}

impl ResourceFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Iam => "iam",
            Self::Event => "event",
            Self::Data => "data",
            Self::Network => "network",
            Self::Ai => "ai",
        }
    }
}

/// Comparison operations supported within RQL filter clauses.
#[derive(Debug, Clone, PartialEq)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    In(Vec<String>),
    NotIn(Vec<String>),
    Contains,
    StartsWith,
    IsTrue,
    IsFalse,
    IsEmpty,
    IsNotEmpty,
}

/// Single field comparison expression in RQL.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldPredicate {
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

/// Boolean expression tree for RQL WHERE clauses.
#[derive(Debug, Clone, PartialEq)]
pub enum RqlExpr {
    Predicate(FieldPredicate),
    Not(Box<RqlExpr>),
    And(Vec<RqlExpr>),
    Or(Vec<RqlExpr>),
}

/// Parsed RQL Abstract Syntax Tree representation.
#[derive(Debug, Clone, PartialEq)]
pub struct RqlQuery {
    pub family: ResourceFamily,
    pub target: String,
    pub filter: Option<RqlExpr>,
    pub limit: Option<usize>,
}

impl RqlQuery {
    /// Backward-compatible list of top-level field predicates.
    pub fn predicates(&self) -> Vec<FieldPredicate> {
        let mut list = Vec::new();
        if let Some(ref expr) = self.filter {
            collect_predicates(expr, &mut list);
        }
        list
    }

    /// Parses a standard RQL statement into an executable AST query plan.
    pub fn parse(input: &str) -> Result<Self, RqlError> {
        let mut trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(RqlError::ParseError(0, "Empty RQL statement".into()));
        }

        // Optional LIMIT clause parsing
        let mut limit = None;
        if let Some(pos) = find_top_level_keyword(trimmed, " limit ") {
            let limit_str = trimmed[pos + 7..].trim();
            if let Ok(n) = limit_str.parse::<usize>() {
                limit = Some(n);
                trimmed = trimmed[..pos].trim();
            }
        }

        let lower = trimmed.to_lowercase();
        let (family, rest) = if lower.starts_with("config from ") {
            (ResourceFamily::Config, &trimmed[12..])
        } else if lower.starts_with("iam from ") {
            (ResourceFamily::Iam, &trimmed[9..])
        } else if lower.starts_with("event from ") {
            (ResourceFamily::Event, &trimmed[11..])
        } else if lower.starts_with("data from ") {
            (ResourceFamily::Data, &trimmed[10..])
        } else if lower.starts_with("network from ") {
            (ResourceFamily::Network, &trimmed[13..])
        } else if lower.starts_with("ai from ") {
            (ResourceFamily::Ai, &trimmed[8..])
        } else if lower == "config from" {
            (ResourceFamily::Config, "")
        } else if lower == "iam from" {
            (ResourceFamily::Iam, "")
        } else if lower == "event from" {
            (ResourceFamily::Event, "")
        } else if lower == "data from" {
            (ResourceFamily::Data, "")
        } else if lower == "network from" {
            (ResourceFamily::Network, "")
        } else if lower == "ai from" {
            (ResourceFamily::Ai, "")
        } else {
            return Err(RqlError::ParseError(0, "Statement must start with a valid RQL clause ('config from', 'iam from', 'event from', 'data from', 'network from', 'ai from')".into()));
        };

        let (target, where_clause) = if let Some(idx) = find_top_level_keyword(rest, " where ") {
            let target_part = rest[..idx].trim().to_string();
            let where_part = rest[idx + 7..].trim();
            (target_part, Some(where_part))
        } else {
            (rest.trim().to_string(), None)
        };

        let filter = if let Some(clause) = where_clause {
            if clause.is_empty() {
                None
            } else {
                Some(parse_where_clause(clause)?)
            }
        } else {
            None
        };

        Ok(RqlQuery {
            family,
            target,
            filter,
            limit,
        })
    }

    /// Evaluates whether an ingested cloud resource matches the query predicates.
    pub fn evaluate(&self, resource: &CloudResource) -> bool {
        if let Some(ref expr) = self.filter {
            evaluate_expr(expr, resource)
        } else {
            true
        }
    }
}

fn collect_predicates(expr: &RqlExpr, list: &mut Vec<FieldPredicate>) {
    match expr {
        RqlExpr::Predicate(p) => list.push(p.clone()),
        RqlExpr::Not(inner) => collect_predicates(inner, list),
        RqlExpr::And(items) | RqlExpr::Or(items) => {
            for item in items {
                collect_predicates(item, list);
            }
        }
    }
}

fn find_top_level_keyword(s: &str, keyword: &str) -> Option<usize> {
    let mut depth = 0;
    let mut quote_char: Option<u8> = None;
    let kw_len = keyword.len();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote_char {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                quote_char = None;
            }
        } else if b == b'\'' || b == b'"' {
            quote_char = Some(b);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' && depth > 0 {
            depth -= 1;
        } else if depth == 0 && i + kw_len <= bytes.len() {
            if s.is_char_boundary(i) && s.is_char_boundary(i + kw_len) {
                if s[i..i + kw_len].eq_ignore_ascii_case(keyword) {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn split_top_level<'a>(s: &'a str, delim: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut quote_char: Option<u8> = None;
    let mut start = 0;
    let delim_len = delim.len();

    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote_char {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                quote_char = None;
            }
        } else if b == b'\'' || b == b'"' {
            quote_char = Some(b);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' && depth > 0 {
            depth -= 1;
        } else if depth == 0 && i + delim_len <= bytes.len() {
            if s.is_char_boundary(i) && s.is_char_boundary(i + delim_len) {
                if s[i..i + delim_len].eq_ignore_ascii_case(delim) {
                    parts.push(&s[start..i]);
                    start = i + delim_len;
                    i = start;
                    continue;
                }
            }
        }
        i += 1;
    }

    if start < s.len() {
        parts.push(&s[start..]);
    }
    parts
}

fn parse_where_clause(clause: &str) -> Result<RqlExpr, RqlError> {
    // Parse top-level OR expressions
    let or_parts = split_top_level(clause, " or ");
    if or_parts.len() > 1 {
        let mut items = Vec::new();
        for p in or_parts {
            items.push(parse_where_clause(p.trim())?);
        }
        return Ok(RqlExpr::Or(items));
    }

    // Parse top-level AND expressions
    let and_parts = split_top_level(clause, " and ");
    if and_parts.len() > 1 {
        let mut items = Vec::new();
        for p in and_parts {
            items.push(parse_where_clause(p.trim())?);
        }
        return Ok(RqlExpr::And(items));
    }

    let trimmed = clause.trim();
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        // Strip matched outer parentheses only if they enclose the whole expression
        let mut depth = 0;
        let mut quote_char: Option<u8> = None;
        let bytes = trimmed.as_bytes();
        let mut closes_at_end = true;
        let mut idx = 0;
        while idx < bytes.len() {
            let b = bytes[idx];
            if let Some(q) = quote_char {
                if b == b'\\' && idx + 1 < bytes.len() {
                    idx += 2;
                    continue;
                }
                if b == q {
                    quote_char = None;
                }
            } else if b == b'\'' || b == b'"' {
                quote_char = Some(b);
            } else if b == b'(' {
                depth += 1;
            } else if b == b')' {
                depth -= 1;
                if depth == 0 && idx < bytes.len() - 1 {
                    closes_at_end = false;
                    break;
                }
            }
            idx += 1;
        }
        if closes_at_end && depth == 0 {
            let inner = &trimmed[1..trimmed.len() - 1].trim();
            return parse_where_clause(inner);
        }
    }

    if trimmed.to_lowercase().starts_with("not ") {
        let inner = parse_where_clause(&trimmed[4..].trim())?;
        return Ok(RqlExpr::Not(Box::new(inner)));
    }

    // Single predicate term
    let pred = parse_single_predicate(trimmed)?;
    Ok(RqlExpr::Predicate(pred))
}

fn parse_single_predicate(term: &str) -> Result<FieldPredicate, RqlError> {
    let term_trimmed = term.trim();
    let term_lower = term_trimmed.to_lowercase();

    if term_lower.starts_with("cloud.type") {
        let val = extract_literal(term_trimmed);
        return Ok(FieldPredicate::CloudType(val));
    }
    if term_lower.starts_with("api.name") {
        let val = extract_literal(term_trimmed);
        return Ok(FieldPredicate::ApiName(val));
    }
    if term_lower.starts_with("region") {
        let val = extract_literal(term_trimmed);
        return Ok(FieldPredicate::Region(val));
    }
    if term_lower.starts_with("account_id") || term_lower.starts_with("account.id") {
        let val = extract_literal(term_trimmed);
        return Ok(FieldPredicate::AccountId(val));
    }
    if term_lower.starts_with("json.rule") {
        let rule_expr = if let Some(eq_pos) = term_trimmed.find('=') {
            term_trimmed[eq_pos + 1..].trim()
        } else {
            term_trimmed
        };
        return parse_json_rule(rule_expr);
    }

    parse_json_rule(term_trimmed)
}

fn extract_literal(expr: &str) -> String {
    let mut open_quote: Option<char> = None;
    let mut chars = expr.chars();
    let mut out = String::new();
    while let Some(c) = chars.next() {
        if let Some(q) = open_quote {
            if c == '\\' {
                if let Some(next_c) = chars.next() {
                    out.push(next_c);
                }
            } else if c == q {
                return out;
            } else {
                out.push(c);
            }
        } else if c == '\'' || c == '"' {
            open_quote = Some(c);
        }
    }
    if open_quote.is_some() {
        return out;
    }
    if let Some(pos) = expr.find('=') {
        expr[pos + 1..].trim().trim_matches('\'').trim_matches('"').to_string()
    } else {
        expr.trim().trim_matches('\'').trim_matches('"').to_string()
    }
}

fn parse_json_rule(expr: &str) -> Result<FieldPredicate, RqlError> {
    let lower = expr.to_lowercase();

    if lower.ends_with("is false") {
        let path_str = expr[..expr.len() - 8].trim();
        let path = parse_path(path_str);
        return Ok(FieldPredicate::JsonRule {
            path,
            op: ComparisonOp::IsFalse,
            target_value: None,
        });
    }

    if lower.ends_with("is true") {
        let path_str = expr[..expr.len() - 7].trim();
        let path = parse_path(path_str);
        return Ok(FieldPredicate::JsonRule {
            path,
            op: ComparisonOp::IsTrue,
            target_value: None,
        });
    }

    if lower.ends_with("is empty") {
        let path_str = expr[..expr.len() - 8].trim();
        let path = parse_path(path_str);
        return Ok(FieldPredicate::JsonRule {
            path,
            op: ComparisonOp::IsEmpty,
            target_value: None,
        });
    }

    if lower.ends_with("is not empty") {
        let path_str = expr[..expr.len() - 12].trim();
        let path = parse_path(path_str);
        return Ok(FieldPredicate::JsonRule {
            path,
            op: ComparisonOp::IsNotEmpty,
            target_value: None,
        });
    }

    if let Some(pos) = lower.find(" not in ") {
        let path_str = expr[..pos].trim();
        let list_str = &expr[pos + 8..].trim();
        let items = parse_literal_list(list_str);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::NotIn(items),
            target_value: None,
        });
    }

    if let Some(pos) = lower.find(" in ") {
        let path_str = expr[..pos].trim();
        let list_str = &expr[pos + 4..].trim();
        let items = parse_literal_list(list_str);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::In(items),
            target_value: None,
        });
    }

    if let Some(pos) = lower.find(" contains ") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 10..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::Contains,
            target_value: Some(val),
        });
    }

    if let Some(pos) = lower.find(" starts with ") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 13..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::StartsWith,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find(">=") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 2..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::GreaterThanOrEqual,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find("<=") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 2..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::LessThanOrEqual,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find('>') {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 1..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::GreaterThan,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find('<') {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 1..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::LessThan,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find("!=") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 2..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::NotEqual,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find("==") {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 2..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::Equal,
            target_value: Some(val),
        });
    }

    if let Some(pos) = expr.find('=') {
        let path_str = expr[..pos].trim();
        let val = extract_literal(&expr[pos + 1..]);
        return Ok(FieldPredicate::JsonRule {
            path: parse_path(path_str),
            op: ComparisonOp::Equal,
            target_value: Some(val),
        });
    }

    Ok(FieldPredicate::RawExpression(expr.to_string()))
}

fn parse_path(s: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let cleaned = s.replace("[].", "[*].");
    for part in cleaned.split('.') {
        let p = part.trim();
        if p.ends_with("[*]") {
            let base = &p[..p.len() - 3];
            if !base.is_empty() {
                segments.push(base.to_string());
            }
            segments.push("[*]".to_string());
        } else if p.ends_with("[]") {
            let base = &p[..p.len() - 2];
            if !base.is_empty() {
                segments.push(base.to_string());
            }
            segments.push("[*]".to_string());
        } else if !p.is_empty() {
            segments.push(p.to_string());
        }
    }
    segments
}

fn parse_literal_list(s: &str) -> Vec<String> {
    let inner = s.trim().trim_start_matches('(').trim_end_matches(')').trim();
    inner
        .split(',')
        .map(|item| item.trim().trim_matches('\'').trim_matches('"').to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn evaluate_expr(expr: &RqlExpr, res: &CloudResource) -> bool {
    match expr {
        RqlExpr::Predicate(p) => evaluate_predicate(p, res),
        RqlExpr::Not(inner) => !evaluate_expr(inner, res),
        RqlExpr::And(items) => items.iter().all(|item| evaluate_expr(item, res)),
        RqlExpr::Or(items) => items.iter().any(|item| evaluate_expr(item, res)),
    }
}

fn evaluate_predicate(pred: &FieldPredicate, resource: &CloudResource) -> bool {
    match pred {
        FieldPredicate::CloudType(expected) => {
            resource.provider.to_string().eq_ignore_ascii_case(expected)
        }
        FieldPredicate::ApiName(expected) => {
            resource.resource_type.eq_ignore_ascii_case(expected)
                || resource.service.eq_ignore_ascii_case(expected)
        }
        FieldPredicate::Region(expected) => {
            resource.region.eq_ignore_ascii_case(expected)
        }
        FieldPredicate::AccountId(expected) => {
            resource.account_id == *expected
        }
        FieldPredicate::JsonRule {
            path,
            op,
            target_value,
        } => {
            let observed_values = resolve_json_path_multi(&resource.state, path);
            if observed_values.is_empty() {
                // If path not found
                return match op {
                    ComparisonOp::IsFalse => true,
                    ComparisonOp::IsEmpty => true,
                    ComparisonOp::NotEqual => true,
                    ComparisonOp::NotIn(_) => true,
                    _ => false,
                };
            }
            observed_values.iter().any(|obs| evaluate_json_match(Some(obs), op, target_value.as_deref()))
        }
        FieldPredicate::RawExpression(expr) => {
            let serialized = serde_json::to_string(&resource.state).unwrap_or_default();
            serialized.contains(expr)
        }
    }
}

fn resolve_json_path_multi<'a>(root: &'a serde_json::Value, path: &[String]) -> Vec<&'a serde_json::Value> {
    let mut current_nodes = vec![root];

    for segment in path {
        let mut next_nodes = Vec::new();
        if segment == "[*]" || segment == "[]" {
            for node in current_nodes {
                if let serde_json::Value::Array(arr) = node {
                    for item in arr {
                        next_nodes.push(item);
                    }
                }
            }
        } else {
            for node in current_nodes {
                match node {
                    serde_json::Value::Object(map) => {
                        if let Some(val) = map.get(segment) {
                            next_nodes.push(val);
                        }
                    }
                    serde_json::Value::Array(arr) => {
                        if let Ok(idx) = segment.parse::<usize>() {
                            if let Some(val) = arr.get(idx) {
                                next_nodes.push(val);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        current_nodes = next_nodes;
        if current_nodes.is_empty() {
            break;
        }
    }

    current_nodes
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
        ComparisonOp::IsEmpty => match observed {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::String(s)) => s.is_empty(),
            Some(serde_json::Value::Array(a)) => a.is_empty(),
            Some(serde_json::Value::Object(o)) => o.is_empty(),
            _ => false,
        },
        ComparisonOp::IsNotEmpty => match observed {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::String(s)) => !s.is_empty(),
            Some(serde_json::Value::Array(a)) => !a.is_empty(),
            Some(serde_json::Value::Object(o)) => !o.is_empty(),
            _ => true,
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
        ComparisonOp::GreaterThan => match (observed, target) {
            (Some(serde_json::Value::Number(n)), Some(t)) => {
                if let (Some(n_f), Ok(t_f)) = (n.as_f64(), t.parse::<f64>()) {
                    n_f > t_f
                } else {
                    false
                }
            }
            _ => false,
        },
        ComparisonOp::GreaterThanOrEqual => match (observed, target) {
            (Some(serde_json::Value::Number(n)), Some(t)) => {
                if let (Some(n_f), Ok(t_f)) = (n.as_f64(), t.parse::<f64>()) {
                    n_f >= t_f
                } else {
                    false
                }
            }
            _ => false,
        },
        ComparisonOp::LessThan => match (observed, target) {
            (Some(serde_json::Value::Number(n)), Some(t)) => {
                if let (Some(n_f), Ok(t_f)) = (n.as_f64(), t.parse::<f64>()) {
                    n_f < t_f
                } else {
                    false
                }
            }
            _ => false,
        },
        ComparisonOp::LessThanOrEqual => match (observed, target) {
            (Some(serde_json::Value::Number(n)), Some(t)) => {
                if let (Some(n_f), Ok(t_f)) = (n.as_f64(), t.parse::<f64>()) {
                    n_f <= t_f
                } else {
                    false
                }
            }
            _ => false,
        },
        ComparisonOp::In(list) => match observed {
            Some(serde_json::Value::String(s)) => list.iter().any(|item| item.eq_ignore_ascii_case(s)),
            Some(serde_json::Value::Number(n)) => list.iter().any(|item| item == &n.to_string()),
            _ => false,
        },
        ComparisonOp::NotIn(list) => match observed {
            Some(serde_json::Value::String(s)) => !list.iter().any(|item| item.eq_ignore_ascii_case(s)),
            Some(serde_json::Value::Number(n)) => !list.iter().any(|item| item == &n.to_string()),
            None => true,
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
        ComparisonOp::StartsWith => match (observed, target) {
            (Some(serde_json::Value::String(s)), Some(t)) => s.starts_with(t),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudsecure_types::CloudProvider;
    use serde_json::json;

    #[test]
    fn test_parse_rql_all_families() {
        let q = RqlQuery::parse("config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket'").unwrap();
        assert_eq!(q.family, ResourceFamily::Config);
        assert_eq!(q.target, "cloud.resource");

        let q = RqlQuery::parse("iam from cloud.entitlements where source.type = 'role'").unwrap();
        assert_eq!(q.family, ResourceFamily::Iam);

        let q = RqlQuery::parse("event from cloud.audit_logs where operation = 'ConsoleLogin'").unwrap();
        assert_eq!(q.family, ResourceFamily::Event);

        let q = RqlQuery::parse("data from cloud.data_store where data.classification in ('PII', 'PCI')").unwrap();
        assert_eq!(q.family, ResourceFamily::Data);

        let q = RqlQuery::parse("network from vpc.flow_record where dest.port in (22, 3389)").unwrap();
        assert_eq!(q.family, ResourceFamily::Network);

        let q = RqlQuery::parse("ai from pipeline.model where model.provider == 'huggingface'").unwrap();
        assert_eq!(q.family, ResourceFamily::Ai);
    }

    #[test]
    fn test_parse_quote_and_limit() {
        let q = RqlQuery::parse("config from cloud.resource where json.rule = description contains 'it\\'s where you look' limit 25").unwrap();
        assert_eq!(q.limit, Some(25));
        assert_eq!(q.target, "cloud.resource");
        let preds = q.predicates();
        assert_eq!(preds.len(), 1);
        match &preds[0] {
            FieldPredicate::JsonRule { op, target_value, .. } => {
                assert_eq!(*op, ComparisonOp::Contains);
                assert_eq!(target_value.as_deref(), Some("it's where you look"));
            }
            other => panic!("Expected JsonRule predicate, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_nested_boolean_algebra() {
        let q = RqlQuery::parse("config from cloud.resource where (cloud.type = 'aws' or cloud.type = 'gcp') and api.name = 'bucket'").unwrap();
        assert!(q.filter.is_some());
    }

    #[test]
    fn test_evaluate_resource() {
        let q = RqlQuery::parse("config from cloud.resource where cloud.type = 'aws' and api.name = 'aws-s3-bucket' and json.rule = publicAccessBlockConfiguration.restrictPublicBuckets is false").unwrap();
        let res = CloudResource {
            id: "test-bucket".into(),
            arn: "arn:aws:s3:::test-bucket".into(),
            name: "test-bucket".into(),
            provider: CloudProvider::Aws,
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            resource_type: "aws-s3-bucket".into(),
            state: json!({
                "publicAccessBlockConfiguration": {
                    "restrictPublicBuckets": false
                }
            }),
            tags: std::collections::HashMap::new(),
        };
        assert!(q.evaluate(&res));

        let res_clean = CloudResource {
            id: "clean-bucket".into(),
            arn: "arn:aws:s3:::clean-bucket".into(),
            name: "clean-bucket".into(),
            provider: CloudProvider::Aws,
            account_id: "123456789012".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
            resource_type: "aws-s3-bucket".into(),
            state: json!({
                "publicAccessBlockConfiguration": {
                    "restrictPublicBuckets": true
                }
            }),
            tags: std::collections::HashMap::new(),
        };
        assert!(!q.evaluate(&res_clean));
    }
}
