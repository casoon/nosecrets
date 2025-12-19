use console::style;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::{self, Write};
use thiserror::Error;

use nosecrets_rules::Severity;

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub fingerprint: String,
    pub preview: String,
}

#[derive(Debug, Default)]
pub struct Report {
    findings: Vec<Finding>,
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("failed to write output: {0}")]
    Io(#[from] io::Error),
    #[error("failed to serialize json: {0}")]
    Json(#[from] serde_json::Error),
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        let deduped = dedup_findings(findings);
        Self { findings: deduped }
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn exit_code(&self) -> i32 {
        if self
            .findings
            .iter()
            .any(|finding| finding.severity.blocks())
        {
            1
        } else {
            0
        }
    }

    pub fn print_terminal(&self) -> Result<(), ReportError> {
        let mut out = io::stdout();
        if self.findings.is_empty() {
            writeln!(out, "{}", style("No secrets found").green())?;
            return Ok(());
        }
        for finding in &self.findings {
            let severity = match finding.severity {
                Severity::Critical => style("CRITICAL").red().bold(),
                Severity::High => style("HIGH").red(),
                Severity::Medium => style("MEDIUM").yellow(),
                Severity::Low => style("LOW").blue(),
            };
            writeln!(
                out,
                "{}:{}:{} [{}] {} ({}) {}",
                finding.path,
                finding.line,
                finding.column,
                severity,
                finding.rule_name,
                finding.rule_id,
                style(&finding.fingerprint).dim()
            )?;
            writeln!(out, "  preview: {}", style(&finding.preview).dim())?;
        }
        Ok(())
    }

    pub fn print_json(&self) -> Result<(), ReportError> {
        let mut out = io::stdout();
        let json = serde_json::to_string_pretty(&self.findings)?;
        writeln!(out, "{}", json)?;
        Ok(())
    }
}

pub fn fingerprint_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    format!("nsi_{}", &hex[..12])
}

pub fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        return "".to_string();
    }
    if secret.len() <= 8 {
        return "*".repeat(secret.len());
    }
    let start = &secret[..4];
    let end = &secret[secret.len() - 4..];
    format!("{}...{}", start, end)
}

fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    let mut output = Vec::new();
    for finding in findings {
        let key = (
            finding.path.clone(),
            finding.line,
            finding.column,
            finding.fingerprint.clone(),
            finding.rule_id.clone(),
        );
        if seen.insert(key) {
            output.push(finding);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use nosecrets_rules::Severity;

    #[test]
    fn fingerprint_is_stable_and_short() {
        let fp = fingerprint_secret("secret");
        assert!(fp.starts_with("nsi_"));
        assert_eq!(fp.len(), 16);
        assert_eq!(fp, fingerprint_secret("secret"));
    }

    #[test]
    fn mask_secret_obscures_middle() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("short"), "*****");
        assert_eq!(mask_secret("longsecret"), "long...cret");
    }

    #[test]
    fn report_dedup_and_exit_code() {
        let finding = Finding {
            path: "src/main.rs".to_string(),
            line: 1,
            column: 5,
            rule_id: "test".to_string(),
            rule_name: "Test".to_string(),
            severity: Severity::High,
            fingerprint: "nsi_abcdef123456".to_string(),
            preview: "sec...ret".to_string(),
        };
        let report = Report::new(vec![finding.clone(), finding]);
        assert_eq!(report.findings().len(), 1);
        assert_eq!(report.exit_code(), 1);
    }
}
