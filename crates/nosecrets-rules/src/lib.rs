use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn blocks(self) -> bool {
        matches!(self, Severity::Critical | Severity::High | Severity::Medium)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub pattern: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_capture")]
    pub capture: usize,
    #[serde(default)]
    pub validate: Option<RuleValidate>,
    #[serde(default)]
    pub paths: Option<RulePaths>,
    #[serde(default)]
    pub allow: Option<RuleAllow>,
}

fn default_capture() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleValidate {
    #[serde(default)]
    pub prefix: Vec<String>,
    pub charset: Option<String>,
    pub length: Option<usize>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RulePaths {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleAllow {
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("failed to parse rules from {source}: {error}")]
    Parse {
        source: String,
        #[source]
        error: toml::de::Error,
    },
}

pub fn load_builtin_rules() -> Result<Vec<Rule>, RulesError> {
    let mut rules = Vec::new();
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/cloud.toml"
        )),
        "rules/cloud.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/deploy.toml"
        )),
        "rules/deploy.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/code.toml"
        )),
        "rules/code.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/database.toml"
        )),
        "rules/database.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/generic.toml"
        )),
        "rules/generic.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rules/payment.toml"
        )),
        "rules/payment.toml",
    )?);
    Ok(rules)
}

pub fn parse_rules(content: &str, source: &str) -> Result<Vec<Rule>, RulesError> {
    let parsed: RulesFile = toml::from_str(content).map_err(|error| RulesError::Parse {
        source: source.to_string(),
        error,
    })?;
    Ok(parsed.rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rules_minimal() {
        let toml = r#"
            [[rule]]
            id = "test"
            name = "Test Rule"
            severity = "high"
            pattern = '''(test_[A-Za-z0-9]+)'''
        "#;
        let rules = parse_rules(toml, "inline").expect("parse rules");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.id, "test");
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.severity, Severity::High);
        assert_eq!(rule.capture, 1);
        assert_eq!(rule.keywords.len(), 0);
    }
}
