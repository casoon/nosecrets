use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use anyhow::{anyhow, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use regex::Regex;

use nosecrets_filter::{normalize_path, Filter};
use nosecrets_report::{fingerprint_secret, mask_secret, Finding};
use nosecrets_rules::{Rule, RuleAllow, RulePaths, RuleValidate};

pub struct Detector {
    rules: Arc<Vec<CompiledRule>>,
    prefilter: Prefilter,
    filter: Arc<Filter>,
}

struct CompiledRule {
    rule: Rule,
    regex: Regex,
    allow_patterns: Vec<Regex>,
    allow_values: HashSet<String>,
    include_paths: Option<GlobSet>,
    exclude_paths: Option<GlobSet>,
    charset_regex: Option<Regex>,
}

struct Prefilter {
    ac: Option<AhoCorasick>,
    keyword_rules: Vec<Vec<usize>>,
    always_rules: Vec<usize>,
}

impl Detector {
    pub fn new(rules: Vec<Rule>, filter: Filter) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            let regex = Regex::new(&rule.pattern)
                .with_context(|| format!("invalid regex for rule {}", rule.id))?;
            let (allow_patterns, allow_values) = compile_rule_allow(rule.allow.as_ref())?;
            let (include_paths, exclude_paths) = compile_rule_paths(rule.paths.as_ref())?;
            let charset_regex = compile_charset(rule.validate.as_ref())?;
            compiled.push(CompiledRule {
                rule,
                regex,
                allow_patterns,
                allow_values,
                include_paths,
                exclude_paths,
                charset_regex,
            });
        }
        let compiled = Arc::new(compiled);
        let prefilter = Prefilter::new(&compiled);
        Ok(Self {
            rules: compiled,
            prefilter,
            filter: Arc::new(filter),
        })
    }

    pub fn scan_files(&self, root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
        let findings: Vec<Finding> = files
            .par_iter()
            .flat_map(|path| match self.scan_file(root, path) {
                Ok(results) => results,
                Err(error) => {
                    eprintln!("nosecrets: failed to scan {}: {}", path.display(), error);
                    Vec::new()
                }
            })
            .collect();
        Ok(findings)
    }

    fn scan_file(&self, root: &Path, path: &Path) -> Result<Vec<Finding>> {
        let rel_path = path.strip_prefix(root).unwrap_or(path);
        if self.filter.is_path_ignored(rel_path) {
            return Ok(Vec::new());
        }
        let content = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        if content.contains(&0) {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&content);
        let line_starts = build_line_starts(&text);
        let mut findings = Vec::new();

        let candidate_rules = self.prefilter.candidates(&text);
        for &rule_idx in &candidate_rules {
            let rule = &self.rules[rule_idx];
            if !rule.applies_to_path(rel_path) {
                continue;
            }
            for caps in rule.regex.captures_iter(&text) {
                let Some(matched) = caps.get(rule.rule.capture) else {
                    continue;
                };
                let secret = matched.as_str();
                if !validate_secret(&rule.rule.validate, rule.charset_regex.as_ref(), secret) {
                    continue;
                }
                if rule.is_allowed(secret) || self.filter.is_value_allowed(secret) {
                    continue;
                }
                let (line, column) = line_col(&line_starts, matched.start());
                let line_text = line_slice(&text, &line_starts, line);
                if Filter::is_inline_ignored(line_text) {
                    continue;
                }
                let fingerprint = fingerprint_secret(secret);
                if self.filter.is_fingerprint_ignored(&fingerprint, rel_path) {
                    continue;
                }
                findings.push(Finding {
                    path: normalize_path(rel_path),
                    line,
                    column,
                    rule_id: rule.rule.id.clone(),
                    rule_name: rule.rule.name.clone(),
                    severity: rule.rule.severity,
                    fingerprint,
                    preview: mask_secret(secret),
                });
            }
        }
        Ok(findings)
    }
}

impl CompiledRule {
    fn applies_to_path(&self, path: &Path) -> bool {
        let normalized = normalize_path(path);
        if let Some(include) = &self.include_paths {
            if !include.is_match(&normalized) {
                return false;
            }
        }
        if let Some(exclude) = &self.exclude_paths {
            if exclude.is_match(&normalized) {
                return false;
            }
        }
        true
    }

    fn is_allowed(&self, secret: &str) -> bool {
        if self.allow_values.contains(secret) {
            return true;
        }
        self.allow_patterns
            .iter()
            .any(|regex| regex.is_match(secret))
    }
}

impl Prefilter {
    fn new(rules: &[CompiledRule]) -> Self {
        let mut keyword_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut always_rules = Vec::new();
        for (idx, rule) in rules.iter().enumerate() {
            if rule.rule.keywords.is_empty() {
                always_rules.push(idx);
                continue;
            }
            for keyword in &rule.rule.keywords {
                keyword_map
                    .entry(keyword.to_string())
                    .or_default()
                    .push(idx);
            }
        }
        let keywords: Vec<String> = keyword_map.keys().cloned().collect();
        let keyword_rules: Vec<Vec<usize>> = keywords
            .iter()
            .map(|keyword| keyword_map.get(keyword).cloned().unwrap_or_default())
            .collect();
        let ac = if keywords.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .build(&keywords)
                .ok()
        };
        Self {
            ac,
            keyword_rules,
            always_rules,
        }
    }

    fn candidates(&self, text: &str) -> Vec<usize> {
        let mut candidates: HashSet<usize> = self.always_rules.iter().copied().collect();
        let Some(ac) = &self.ac else {
            return candidates.into_iter().collect();
        };
        for mat in ac.find_iter(text) {
            let idx = mat.pattern().as_usize();
            if let Some(rules) = self.keyword_rules.get(idx) {
                candidates.extend(rules.iter().copied());
            }
        }
        candidates.into_iter().collect()
    }
}

fn compile_rule_allow(allow: Option<&RuleAllow>) -> Result<(Vec<Regex>, HashSet<String>)> {
    let Some(allow) = allow else {
        return Ok((Vec::new(), HashSet::new()));
    };
    let mut patterns = Vec::new();
    for pattern in &allow.patterns {
        patterns.push(
            Regex::new(pattern)
                .with_context(|| format!("invalid allow regex pattern {pattern}"))?,
        );
    }
    let values = allow.values.iter().cloned().collect();
    Ok((patterns, values))
}

fn compile_rule_paths(paths: Option<&RulePaths>) -> Result<(Option<GlobSet>, Option<GlobSet>)> {
    let Some(paths) = paths else {
        return Ok((None, None));
    };
    let include = build_globset(&paths.include)?;
    let exclude = build_globset(&paths.exclude)?;
    Ok((include, exclude))
}

fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let normalized = normalize_glob_pattern(pattern);
        let glob =
            Glob::new(&normalized).with_context(|| format!("invalid glob pattern {normalized}"))?;
        builder.add(glob);
    }
    Ok(Some(
        builder.build().with_context(|| "failed to build globset")?,
    ))
}

fn compile_charset(validate: Option<&RuleValidate>) -> Result<Option<Regex>> {
    let Some(validate) = validate else {
        return Ok(None);
    };
    let Some(charset) = &validate.charset else {
        return Ok(None);
    };
    let pattern = format!("^[{}]+$", charset);
    Ok(Some(Regex::new(&pattern).with_context(|| {
        format!("invalid charset regex {pattern}")
    })?))
}

fn validate_secret(validate: &Option<RuleValidate>, charset: Option<&Regex>, secret: &str) -> bool {
    let Some(validate) = validate else {
        return true;
    };
    if let Some(length) = validate.length {
        if secret.len() != length {
            return false;
        }
    }
    if let Some(min) = validate.min_length {
        if secret.len() < min {
            return false;
        }
    }
    if let Some(max) = validate.max_length {
        if secret.len() > max {
            return false;
        }
    }
    if !validate.prefix.is_empty()
        && !validate
            .prefix
            .iter()
            .any(|prefix| secret.starts_with(prefix))
    {
        return false;
    }
    if let Some(charset_regex) = charset {
        if !charset_regex.is_match(secret) {
            return false;
        }
    }
    true
}

pub fn collect_files(root: &Path, inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let targets: Vec<PathBuf> = if inputs.is_empty() {
        vec![root.to_path_buf()]
    } else {
        inputs.to_vec()
    };

    for target in targets {
        let target = if target.is_absolute() {
            target
        } else {
            root.join(target)
        };
        if target.is_file() {
            if seen.insert(target.clone()) {
                files.push(target);
            }
            continue;
        }
        if target.is_dir() {
            for entry in walkdir::WalkDir::new(&target)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                if entry.file_type().is_file() {
                    let path = entry.path().to_path_buf();
                    if seen.insert(path.clone()) {
                        files.push(path);
                    }
                }
            }
        }
    }

    Ok(files)
}

pub fn discover_repo_root(start: &Path) -> Result<Option<PathBuf>> {
    match gix::discover(start) {
        Ok(repo) => Ok(repo.work_dir().map(|path| path.to_path_buf())),
        Err(_) => Ok(None),
    }
}

pub fn collect_staged_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "--name-only", "--cached", "--diff-filter=ACM"])
        .output()
        .with_context(|| "failed to execute git")?;

    if !output.status.success() {
        return Err(anyhow!(
            "git diff --name-only --cached failed with status {}",
            output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut files = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        files.push(repo_root.join(trimmed));
    }
    Ok(files)
}

fn build_line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in text.as_bytes().iter().enumerate() {
        if *byte == b'\n' {
            starts.push(idx + 1);
        }
    }
    starts
}

fn line_col(line_starts: &[usize], index: usize) -> (usize, usize) {
    let line_idx = match line_starts.binary_search(&index) {
        Ok(idx) => idx,
        Err(idx) => idx.saturating_sub(1),
    };
    let line = line_idx + 1;
    let start = line_starts.get(line_idx).copied().unwrap_or(0);
    let column = index.saturating_sub(start) + 1;
    (line, column)
}

fn line_slice<'a>(text: &'a str, line_starts: &[usize], line: usize) -> &'a str {
    if line == 0 {
        return "";
    }
    let idx = line - 1;
    let start = *line_starts.get(idx).unwrap_or(&0);
    let end = if idx + 1 < line_starts.len() {
        line_starts[idx + 1].saturating_sub(1)
    } else {
        text.len()
    };
    text.get(start..end).unwrap_or("")
}

fn normalize_glob_pattern(pattern: &str) -> String {
    let mut normalized = pattern.replace('\\', "/");
    if normalized.ends_with('/') {
        normalized.push_str("**");
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use nosecrets_filter::Config;
    use nosecrets_rules::{Rule, RuleAllow, RulePaths, Severity};
    use std::fs;
    use tempfile::tempdir;

    fn base_rule(pattern: &str) -> Rule {
        Rule {
            id: "test-rule".to_string(),
            name: "Test Rule".to_string(),
            severity: Severity::High,
            pattern: pattern.to_string(),
            keywords: vec!["secret_".to_string()],
            capture: 1,
            validate: None,
            paths: None,
            allow: None,
        }
    }

    #[test]
    fn detects_secret_with_position() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("src/config.txt");
        fs::create_dir_all(path.parent().unwrap()).expect("create dir");
        let secret = "secret_ABC123";
        let content = format!("let key = \"{}\";\\n", secret);
        fs::write(&path, &content).expect("write file");

        let rule = base_rule(r"(secret_[A-Z0-9]{6})");
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector = Detector::new(vec![rule], filter).expect("detector");

        let findings = detector
            .scan_files(root, std::slice::from_ref(&path))
            .expect("scan");
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        let expected_col = content.find(secret).unwrap() + 1;
        assert_eq!(finding.path, "src/config.txt");
        assert_eq!(finding.line, 1);
        assert_eq!(finding.column, expected_col);
    }

    #[test]
    fn inline_ignore_skips_finding() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("src/ignored.txt");
        fs::create_dir_all(path.parent().unwrap()).expect("create dir");
        let content = "key = \"secret_ABC123\" # @nosecrets-ignore\\n";
        fs::write(&path, content).expect("write file");

        let rule = base_rule(r"(secret_[A-Z0-9]{6})");
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector = Detector::new(vec![rule], filter).expect("detector");

        let findings = detector.scan_files(root, &[path]).expect("scan");
        assert!(findings.is_empty());
    }

    #[test]
    fn allow_patterns_skip_matching_secret() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("src/allowed.txt");
        fs::create_dir_all(path.parent().unwrap()).expect("create dir");
        let content = "key = \"secret_ALLOW\"\\n";
        fs::write(&path, content).expect("write file");

        let mut rule = base_rule(r"(secret_[A-Z]+)");
        rule.allow = Some(RuleAllow {
            patterns: vec!["ALLOW$".to_string()],
            values: Vec::new(),
        });
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector = Detector::new(vec![rule], filter).expect("detector");

        let findings = detector.scan_files(root, &[path]).expect("scan");
        assert!(findings.is_empty());
    }

    #[test]
    fn rule_paths_exclude_skip_file() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("tests/secret.txt");
        fs::create_dir_all(path.parent().unwrap()).expect("create dir");
        fs::write(&path, "secret_ABC123").expect("write file");

        let mut rule = base_rule(r"(secret_[A-Z0-9]{6})");
        rule.paths = Some(RulePaths {
            include: Vec::new(),
            exclude: vec!["tests/".to_string()],
        });
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector = Detector::new(vec![rule], filter).expect("detector");

        let findings = detector.scan_files(root, &[path]).expect("scan");
        assert!(findings.is_empty());
    }

    #[test]
    fn config_ignore_paths_skip_file() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("vendor/secret.txt");
        fs::create_dir_all(path.parent().unwrap()).expect("create dir");
        fs::write(&path, "secret_ABC123").expect("write file");

        let mut config = Config::default();
        config.ignore.paths = vec!["vendor/".to_string()];
        let filter = Filter::from_config(Some(config), Vec::new()).expect("filter");
        let rule = base_rule(r"(secret_[A-Z0-9]{6})");
        let detector = Detector::new(vec![rule], filter).expect("detector");

        let findings = detector.scan_files(root, &[path]).expect("scan");
        assert!(findings.is_empty());
    }
}
