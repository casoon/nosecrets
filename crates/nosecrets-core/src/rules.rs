use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

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

    /// Higher means more severe.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 3,
            Severity::High => 2,
            Severity::Medium => 1,
            Severity::Low => 0,
        }
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
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub pattern: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "default_capture")]
    pub capture: usize,
    /// Marks a catch-all rule. When it matches the same text as a specific rule of equal
    /// severity, the specific rule is reported.
    #[serde(default)]
    pub generic: bool,
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
#[serde(deny_unknown_fields)]
pub struct RuleValidate {
    #[serde(default)]
    pub prefix: Vec<String>,
    pub charset: Option<String>,
    pub length: Option<usize>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RulePaths {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleAllow {
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

pub fn load_builtin_rules() -> Result<Vec<Rule>> {
    let mut rules = Vec::new();
    rules.extend(parse_rules(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/cloud.toml")),
        "rules/cloud.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/deploy.toml")),
        "rules/deploy.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/code.toml")),
        "rules/code.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/database.toml")),
        "rules/database.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/generic.toml")),
        "rules/generic.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rules/payment.toml")),
        "rules/payment.toml",
    )?);
    rules.extend(parse_rules(
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/rules/communication.toml"
        )),
        "rules/communication.toml",
    )?);
    Ok(rules)
}

pub fn parse_rules(content: &str, source: &str) -> Result<Vec<Rule>> {
    let parsed: RulesFile = toml::from_str(content).map_err(|error| Error::ParseRules {
        file: source.to_string(),
        source: error,
    })?;
    for rule in &parsed.rule {
        let reason = if rule.id.trim().is_empty() {
            "id is empty"
        } else if rule.pattern.is_empty() {
            "pattern is empty"
        } else if rule.validate.as_ref().is_some_and(|validate| {
            matches!((validate.min_length, validate.max_length), (Some(min), Some(max)) if min > max)
        }) {
            "min_length is greater than max_length"
        } else {
            continue;
        };
        return Err(Error::InvalidRule {
            file: source.to_string(),
            id: rule.id.clone(),
            reason,
        });
    }
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

    #[test]
    fn builtin_rules_load() {
        assert!(!load_builtin_rules().expect("builtin rules").is_empty());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let misspelled_keywords = r#"
            [[rule]]
            id = "test"
            name = "Test Rule"
            severity = "high"
            pattern = "(test_[a-z]+)"
            keyword = ["test_"]
        "#;
        let error = parse_rules(misspelled_keywords, "inline").expect_err("must fail");
        assert!(format!("{error:?}").contains("keyword"));

        let misspelled_validate = r#"
            [[rule]]
            id = "test"
            name = "Test Rule"
            severity = "high"
            pattern = "(test_[a-z]+)"

            [rule.validate]
            lenght = 10
        "#;
        let error = parse_rules(misspelled_validate, "inline").expect_err("must fail");
        assert!(format!("{error:?}").contains("lenght"));
    }

    #[test]
    fn inconsistent_rules_are_rejected() {
        let rule = |id: &str, pattern: &str, validate: &str| {
            format!(
                "[[rule]]\nid = \"{id}\"\nname = \"T\"\nseverity = \"high\"\npattern = \"{pattern}\"\n{validate}"
            )
        };
        assert!(parse_rules(&rule("", "(a)", ""), "inline").is_err());
        assert!(parse_rules(&rule("x", "", ""), "inline").is_err());
        let bounds = "[rule.validate]\nmin_length = 9\nmax_length = 3\n";
        assert!(parse_rules(&rule("x", "(a)", bounds), "inline").is_err());
    }
}
