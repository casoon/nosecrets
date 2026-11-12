use anstyle::{AnsiColor, Style};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io::{self, Write};

use crate::error::{Error, Result};
use crate::rules::Severity;

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
    /// Set to `base64` when the secret was found inside a decoded token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
}

#[derive(Debug, Default)]
pub struct Report {
    findings: Vec<Finding>,
}

impl Report {
    pub fn new(findings: Vec<Finding>) -> Self {
        let mut deduped = dedup_findings(findings);
        deduped.sort_by(|a, b| {
            (&a.path, a.line, a.column, &a.rule_id).cmp(&(&b.path, b.line, b.column, &b.rule_id))
        });
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

    pub fn print_terminal(&self) -> Result<()> {
        // `anstream` drops the colour codes when stdout is no terminal or `NO_COLOR` is set.
        self.write_terminal(&mut anstream::stdout())
            .map_err(write_error)
    }

    fn write_terminal(&self, out: &mut impl Write) -> io::Result<()> {
        if self.findings.is_empty() {
            let green = AnsiColor::Green.on_default();
            writeln!(out, "{green}No secrets found{green:#}")?;
            return Ok(());
        }
        let dim = Style::new().dimmed();
        for finding in &self.findings {
            let (label, colour) = match finding.severity {
                Severity::Critical => ("CRITICAL", AnsiColor::Red.on_default().bold()),
                Severity::High => ("HIGH", AnsiColor::Red.on_default()),
                Severity::Medium => ("MEDIUM", AnsiColor::Yellow.on_default()),
                Severity::Low => ("LOW", AnsiColor::Blue.on_default()),
            };
            let encoding = finding
                .encoding
                .map(|encoding| format!(" ({encoding})"))
                .unwrap_or_default();
            writeln!(
                out,
                "{}:{}:{} [{colour}{label}{colour:#}] {} ({}) {dim}{}{dim:#}{encoding}",
                finding.path,
                finding.line,
                finding.column,
                finding.rule_name,
                finding.rule_id,
                finding.fingerprint
            )?;
            writeln!(out, "  preview: {dim}{}{dim:#}", finding.preview)?;
        }
        Ok(())
    }

    pub fn print_json(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.findings).map_err(Error::Json)?;
        writeln!(io::stdout(), "{}", json).map_err(write_error)
    }
}

impl Report {
    /// Prints the findings as a SARIF 2.1.0 log, for GitHub code scanning.
    pub fn print_sarif(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.sarif()).map_err(Error::Json)?;
        writeln!(io::stdout(), "{}", json).map_err(write_error)
    }

    fn sarif(&self) -> serde_json::Value {
        // One driver rule per rule id that occurs; `ruleIndex` points into this list.
        let mut rules: BTreeMap<&str, &str> = BTreeMap::new();
        for finding in &self.findings {
            rules.insert(&finding.rule_id, &finding.rule_name);
        }
        let rule_ids: Vec<&str> = rules.keys().copied().collect();
        let driver_rules: Vec<serde_json::Value> = rules
            .iter()
            .map(|(id, name)| {
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "shortDescription": { "text": name },
                })
            })
            .collect();
        let results: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|finding| {
                let level = match finding.severity {
                    Severity::Critical | Severity::High => "error",
                    Severity::Medium => "warning",
                    Severity::Low => "note",
                };
                let rule_index = rule_ids
                    .iter()
                    .position(|id| *id == finding.rule_id)
                    .unwrap_or_default();
                serde_json::json!({
                    "ruleId": finding.rule_id,
                    "ruleIndex": rule_index,
                    "level": level,
                    "message": { "text": format!("{}: {}", finding.rule_name, finding.preview) },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": finding.path },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                            },
                        },
                    }],
                    "partialFingerprints": { "nosecrets/v1": finding.fingerprint },
                })
            })
            .collect();
        serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "nosecrets",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://casoon.github.io/nosecrets/",
                        "rules": driver_rules,
                    },
                },
                "results": results,
            }],
        })
    }
}

fn write_error(source: io::Error) -> Error {
    Error::io("failed to write output", source)
}

pub fn fingerprint_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("nsi_{hex}")
}

/// Masks a secret for display. At most a quarter of the characters is revealed, never more
/// than four at each end; short secrets are hidden completely.
pub fn mask_secret(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let len = chars.len();
    if len < 12 {
        return "*".repeat(len);
    }
    let prefix: String = chars.iter().take((len / 4).min(4)).collect();
    if len < 32 {
        // Prefix only: a suffix as well would exceed a quarter of the secret.
        return format!("{prefix}...");
    }
    let suffix: String = chars[len - 4..].iter().collect();
    format!("{prefix}...{suffix}")
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

    #[test]
    fn fingerprint_is_stable_and_short() {
        let fp = fingerprint_secret("secret");
        assert!(fp.starts_with("nsi_"));
        assert_eq!(fp.len(), 16);
        assert_eq!(fp, fingerprint_secret("secret"));
    }

    #[test]
    fn fingerprint_matches_known_value() {
        // Existing .nosecretsignore entries depend on this exact value.
        assert_eq!(fingerprint_secret("secret"), "nsi_2bb80d537b1d");
        assert_eq!(
            // Split, so the repository's self-scan does not flag this test.
            fingerprint_secret(&["ghp_", "1234567890abcdefghijklmnopqrstuvwxyz"].concat()),
            "nsi_1db61e13c133"
        );
    }

    #[test]
    fn mask_secret_reveals_at_most_a_quarter() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("short"), "*****");
        assert_eq!(mask_secret("hunter2ab"), "*********");
        assert_eq!(mask_secret("abcdefghijkl"), "abc...");
        assert_eq!(mask_secret("abcdefghijklmnop"), "abcd...");
        for len in [8, 9, 12, 16, 31, 32, 40, 200] {
            let secret: String = ('a'..='z').cycle().take(len).collect();
            let masked = mask_secret(&secret);
            let revealed = masked.chars().filter(|c| c.is_ascii_lowercase()).count();
            assert!(revealed * 4 <= len, "{len} chars: {masked}");
        }
        let long: String = ('a'..='z').cycle().take(40).collect();
        assert_eq!(mask_secret(&long), "abcd...klmn");
    }

    #[test]
    fn mask_secret_handles_unicode() {
        assert_eq!(mask_secret("абвгдежзи"), "*********");
        assert_eq!(mask_secret("„quoted-secret-სიმბოლოები"), "„quo...");
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
            encoding: None,
        };
        let report = Report::new(vec![finding.clone(), finding]);
        assert_eq!(report.findings().len(), 1);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn report_sorts_findings() {
        let finding = |path: &str, line: usize| Finding {
            path: path.to_string(),
            line,
            column: 1,
            rule_id: "test".to_string(),
            rule_name: "Test".to_string(),
            severity: Severity::Low,
            fingerprint: format!("nsi_{path}{line}"),
            preview: String::new(),
            encoding: None,
        };
        let report = Report::new(vec![finding("b", 1), finding("a", 9), finding("a", 2)]);
        let order: Vec<(&str, usize)> = report
            .findings()
            .iter()
            .map(|finding| (finding.path.as_str(), finding.line))
            .collect();
        assert_eq!(order, vec![("a", 2), ("a", 9), ("b", 1)]);
    }

    fn sarif_finding(rule_id: &str, severity: Severity, line: usize, secret: &str) -> Finding {
        Finding {
            path: "src/config.py".to_string(),
            line,
            column: 10,
            rule_id: rule_id.to_string(),
            rule_name: format!("Rule {rule_id}"),
            severity,
            fingerprint: fingerprint_secret(secret),
            preview: mask_secret(secret),
        }
    }

    #[test]
    fn sarif_maps_findings() {
        // Split, so the repository's self-scan does not flag this test.
        let secret = ["ghp_", "1234567890abcdefghijklmnopqrstuvwxyz"].concat();
        let report = Report::new(vec![
            sarif_finding("github-pat", Severity::Critical, 3, &secret),
            sarif_finding("entropy", Severity::Low, 7, "xK9mB2vL5nQ8rT3wA7jP1hD6"),
        ]);
        let sarif = report.sarif();
        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "nosecrets");
        assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            driver["informationUri"],
            "https://casoon.github.io/nosecrets/"
        );
        let rules = driver["rules"].as_array().expect("rules");
        let ids: Vec<&str> = rules
            .iter()
            .map(|r| r["id"].as_str().expect("id"))
            .collect();
        assert_eq!(ids, vec!["entropy", "github-pat"]);
        assert_eq!(rules[1]["name"], "Rule github-pat");
        assert_eq!(rules[1]["shortDescription"]["text"], "Rule github-pat");

        let results = run["results"].as_array().expect("results");
        assert_eq!(results.len(), 2);
        let first = &results[0];
        assert_eq!(first["ruleId"], "github-pat");
        assert_eq!(first["ruleIndex"], 1);
        assert_eq!(first["level"], "error");
        assert_eq!(first["message"]["text"], "Rule github-pat: ghp_...wxyz");
        let location = &first["locations"][0]["physicalLocation"];
        assert_eq!(location["artifactLocation"]["uri"], "src/config.py");
        assert_eq!(location["region"]["startLine"], 3);
        assert_eq!(location["region"]["startColumn"], 10);
        assert_eq!(
            first["partialFingerprints"]["nosecrets/v1"],
            "nsi_1db61e13c133"
        );
        assert_eq!(results[1]["level"], "note");
        assert_eq!(results[1]["ruleIndex"], 0);
    }

    #[test]
    fn sarif_levels_follow_severity() {
        let report = Report::new(vec![
            sarif_finding("a", Severity::High, 1, "secret-a"),
            sarif_finding("b", Severity::Medium, 2, "secret-b"),
        ]);
        let sarif = report.sarif();
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
        assert_eq!(sarif["runs"][0]["results"][1]["level"], "warning");
    }

    #[test]
    fn sarif_empty_report_is_valid() {
        let sarif = Report::new(Vec::new()).sarif();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"], serde_json::json!([]));
        assert_eq!(
            sarif["runs"][0]["tool"]["driver"]["rules"],
            serde_json::json!([])
        );
    }

    #[test]
    fn sarif_never_contains_the_secret() {
        let secret = ["ghp_", "1234567890abcdefghijklmnopqrstuvwxyz"].concat();
        let report = Report::new(vec![sarif_finding(
            "github-pat",
            Severity::Critical,
            1,
            &secret,
        )]);
        let text = serde_json::to_string(&report.sarif()).expect("json");
        assert!(!text.contains(&secret));
        assert!(!text.contains("1234567890abcdefghij"));
    }
}
