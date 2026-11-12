use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use globset::GlobSet;
use rayon::prelude::*;
use regex::Regex;

use crate::entropy;
use crate::error::{Error, Result};
use crate::filter::{build_globset, normalize_path, DecodeConfig, EntropyConfig, Filter};
use crate::git::{list_staged_blobs, list_tracked_blobs, load_git_blob_contents, GitBlob};
use crate::report::{fingerprint_secret, mask_secret, Finding};
use crate::rules::{Rule, RuleAllow, RulePaths, RuleValidate, Severity};

pub struct Detector {
    rules: Arc<Vec<CompiledRule>>,
    prefilter: Prefilter,
    filter: Arc<Filter>,
    entropy_config: EntropyConfig,
    entropy_allow_patterns: Vec<Regex>,
    decode: DecodeConfig,
    skipped_large_files: AtomicUsize,
}

struct RegexHit {
    start: usize,
    end: usize,
    rule_idx: usize,
    finding: Finding,
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
        Self::with_entropy(rules, filter, EntropyConfig::default())
    }

    pub fn with_entropy(
        rules: Vec<Rule>,
        filter: Filter,
        entropy_config: EntropyConfig,
    ) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        let mut rule_ids = HashSet::new();
        for rule in rules {
            if !rule_ids.insert(rule.id.clone()) {
                return Err(Error::DuplicateRule(rule.id));
            }
            let regex = Regex::new(&rule.pattern).map_err(|source| {
                Error::regex(format!("invalid regex for rule {}", rule.id), source)
            })?;
            if rule.capture >= regex.captures_len() {
                return Err(Error::MissingCapture {
                    id: rule.id,
                    capture: rule.capture,
                });
            }
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
        let prefilter = Prefilter::new(&compiled)?;

        let mut entropy_allow = Vec::new();
        for pattern in &entropy_config.allow.patterns {
            entropy_allow.push(Regex::new(pattern).map_err(|source| {
                Error::regex(format!("invalid entropy allow pattern {pattern}"), source)
            })?);
        }

        Ok(Self {
            rules: compiled,
            prefilter,
            filter: Arc::new(filter),
            entropy_config,
            entropy_allow_patterns: entropy_allow,
            decode: DecodeConfig::default(),
            skipped_large_files: AtomicUsize::new(0),
        })
    }

    /// Sets which encodings are decoded and scanned (default: base64 on).
    pub fn with_decode(mut self, decode: DecodeConfig) -> Self {
        self.decode = decode;
        self
    }

    /// Number of files skipped so far because they exceed the configured size limit.
    pub fn skipped_large_files(&self) -> usize {
        self.skipped_large_files.load(Ordering::Relaxed)
    }

    /// Like [`collect_files`], but does not descend into ignored directories.
    pub fn collect_files(&self, root: &Path, inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
        walk_inputs(root, inputs, &|dir| {
            self.filter
                .is_dir_ignored(dir.strip_prefix(root).unwrap_or(dir))
        })
    }

    pub fn scan_files(&self, root: &Path, files: &[PathBuf]) -> Result<Vec<Finding>> {
        let findings: Result<Vec<Vec<Finding>>> = files
            .par_iter()
            .map(|path| self.scan_file(root, path))
            .collect();
        Ok(findings?.into_iter().flatten().collect())
    }

    pub fn scan_staged_files(&self, repo_root: &Path) -> Result<Vec<Finding>> {
        let files = list_staged_blobs(repo_root)?;
        self.scan_git_blobs(repo_root, files)
    }

    pub fn scan_tracked_files(&self, repo_root: &Path) -> Result<Vec<Finding>> {
        let files = list_tracked_blobs(repo_root)?;
        self.scan_git_blobs(repo_root, files)
    }

    fn scan_git_blobs(&self, repo_root: &Path, mut files: Vec<GitBlob>) -> Result<Vec<Finding>> {
        files.retain(|file| !self.filter.is_path_ignored(&file.path));
        let listed = files.len();
        let files = load_git_blob_contents(repo_root, files, self.filter.max_file_size())?;
        self.skipped_large_files
            .fetch_add(listed - files.len(), Ordering::Relaxed);
        let findings: Result<Vec<Vec<Finding>>> = files
            .par_iter()
            .map(|file| self.scan_content(repo_root, &file.path, &file.content))
            .collect();
        Ok(findings?.into_iter().flatten().collect())
    }

    fn scan_file(&self, root: &Path, path: &Path) -> Result<Vec<Finding>> {
        if self
            .filter
            .is_path_ignored(path.strip_prefix(root).unwrap_or(path))
        {
            return Ok(Vec::new());
        }
        if let Some(max) = self.filter.max_file_size() {
            let size = fs::metadata(path)
                .map_err(|source| Error::io(format!("reading {}", path.display()), source))?
                .len();
            if size > max {
                self.skipped_large_files.fetch_add(1, Ordering::Relaxed);
                return Ok(Vec::new());
            }
        }
        let content = fs::read(path)
            .map_err(|source| Error::io(format!("reading {}", path.display()), source))?;
        self.scan_content(root, path, &content)
    }

    fn scan_content(&self, root: &Path, path: &Path, content: &[u8]) -> Result<Vec<Finding>> {
        let rel_path = path.strip_prefix(root).unwrap_or(path);
        if content.contains(&0) {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(content);
        let line_starts = build_line_starts(&text);
        let mut hits = Vec::new();

        // Phase 1: Regex-based detection
        let candidate_rules = self.prefilter.candidates(&text);
        for (rule_idx, start, end, secret) in self.rule_matches(&text, rel_path, &candidate_rules) {
            let (line, column) = line_col(&line_starts, start);
            let line_text = line_slice(&text, &line_starts, line);
            if Filter::is_inline_ignored(line_text) {
                continue;
            }
            let fingerprint = fingerprint_secret(secret);
            if self.filter.is_fingerprint_ignored(&fingerprint, rel_path) {
                continue;
            }
            let rule = &self.rules[rule_idx];
            hits.push(RegexHit {
                start,
                end,
                rule_idx,
                finding: Finding {
                    path: normalize_path(rel_path),
                    line,
                    column,
                    rule_id: rule.rule.id.clone(),
                    rule_name: rule.rule.name.clone(),
                    severity: rule.rule.severity,
                    fingerprint,
                    preview: mask_secret(secret),
                    encoding: None,
                },
            });
        }
        let hits = self.best_hit_per_span(hits);
        let mut regex_spans: Vec<(usize, usize)> =
            hits.iter().map(|hit| (hit.start, hit.end)).collect();
        let mut findings: Vec<Finding> = hits.into_iter().map(|hit| hit.finding).collect();

        // Phase 1b: regex rules over base64-decoded tokens (one level, no entropy)
        if self.decode.base64 {
            self.scan_base64(
                &text,
                &line_starts,
                rel_path,
                &mut regex_spans,
                &mut findings,
            );
        }

        // Phase 2: Entropy-based detection
        if self.entropy_config.enabled {
            let entropy_matches =
                entropy::detect_entropy(&text, &self.entropy_config, &self.entropy_allow_patterns);
            for em in entropy_matches {
                let em_end = em.byte_offset + em.text.len();
                // Deduplicate: skip if overlapping with any regex span
                let overlaps = regex_spans
                    .iter()
                    .any(|&(start, end)| em.byte_offset < end && em_end > start);
                if overlaps {
                    continue;
                }
                let (line, column) = line_col(&line_starts, em.byte_offset);
                let line_text = line_slice(&text, &line_starts, line);
                if Filter::is_inline_ignored(line_text) {
                    continue;
                }
                if self.filter.is_value_allowed(&em.text) {
                    continue;
                }
                let fingerprint = fingerprint_secret(&em.text);
                if self.filter.is_fingerprint_ignored(&fingerprint, rel_path) {
                    continue;
                }
                findings.push(Finding {
                    path: normalize_path(rel_path),
                    line,
                    column,
                    rule_id: "high-entropy-string".to_string(),
                    rule_name: "High Entropy String".to_string(),
                    severity: Severity::Medium,
                    fingerprint,
                    preview: mask_secret(&em.text),
                    encoding: None,
                });
            }
        }

        Ok(findings)
    }

    /// Runs the candidate rules over `text` and returns every match that passes path filter,
    /// validation and allowlists, as `(rule index, start, end, secret)`.
    fn rule_matches<'t>(
        &self,
        text: &'t str,
        rel_path: &Path,
        candidate_rules: &[usize],
    ) -> Vec<(usize, usize, usize, &'t str)> {
        let mut matches = Vec::new();
        for &rule_idx in candidate_rules {
            let rule = &self.rules[rule_idx];
            if !rule.applies_to_path(rel_path) {
                continue;
            }
            for caps in rule.regex.captures_iter(text) {
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
                matches.push((rule_idx, matched.start(), matched.end(), secret));
            }
        }
        matches
    }

    /// Decodes base64 candidates and matches the regex rules against the decoded text.
    /// Findings sit at the encoded token; its span is added to `spans` so the entropy layer
    /// skips it. Tokens overlapping a plain finding are skipped.
    fn scan_base64(
        &self,
        text: &str,
        line_starts: &[usize],
        rel_path: &Path,
        spans: &mut Vec<(usize, usize)>,
        findings: &mut Vec<Finding>,
    ) {
        let plain_len = spans.len();
        // A plain finding from a catch-all rule on an encoded token (`api_key: <base64>`) is
        // replaced by what the decoded text reveals; a specific plain finding wins.
        let is_generic = |rule_id: &str| {
            self.rules
                .iter()
                .any(|compiled| compiled.rule.id == rule_id && compiled.rule.generic)
        };
        let mut replaced: Vec<usize> = Vec::new();
        for (start, end) in base64_candidates(text.as_bytes()) {
            let overlapping: Vec<usize> = (0..plain_len)
                .filter(|&i| start < spans[i].1 && end > spans[i].0)
                .collect();
            if overlapping
                .iter()
                .any(|&i| !is_generic(&findings[i].rule_id))
            {
                continue;
            }
            let Some(decoded) = decode_base64(&text.as_bytes()[start..end]) else {
                continue;
            };
            let candidate_rules = self.prefilter.candidates(&decoded);
            let mut hits: Vec<RegexHit> = self
                .rule_matches(&decoded, rel_path, &candidate_rules)
                .into_iter()
                .map(|(rule_idx, s, e, secret)| RegexHit {
                    start: s,
                    end: e,
                    rule_idx,
                    finding: Finding {
                        path: normalize_path(rel_path),
                        line: 0,
                        column: 0,
                        rule_id: self.rules[rule_idx].rule.id.clone(),
                        rule_name: self.rules[rule_idx].rule.name.clone(),
                        severity: self.rules[rule_idx].rule.severity,
                        fingerprint: fingerprint_secret(secret),
                        preview: mask_secret(secret),
                        encoding: Some("base64"),
                    },
                })
                .collect();
            if hits.is_empty() {
                continue;
            }
            let (line, column) = line_col(line_starts, start);
            if Filter::is_inline_ignored(line_slice(text, line_starts, line)) {
                continue;
            }
            hits = self.best_hit_per_span(hits);
            for mut hit in hits {
                if self
                    .filter
                    .is_fingerprint_ignored(&hit.finding.fingerprint, rel_path)
                {
                    continue;
                }
                hit.finding.line = line;
                hit.finding.column = column;
                findings.push(hit.finding);
                spans.push((start, end));
                replaced.extend(&overlapping);
            }
        }
        if !replaced.is_empty() {
            let mut index = 0;
            findings.retain(|_| {
                let keep = !replaced.contains(&index);
                index += 1;
                keep
            });
        }
    }

    /// Keeps one hit per overlapping span: the more severe rule wins, then a specific rule
    /// over a generic one, then the longer match, then the rule id.
    fn best_hit_per_span(&self, mut hits: Vec<RegexHit>) -> Vec<RegexHit> {
        hits.sort_by(|a, b| {
            let (rule_a, rule_b) = (&self.rules[a.rule_idx].rule, &self.rules[b.rule_idx].rule);
            rule_b
                .severity
                .rank()
                .cmp(&rule_a.severity.rank())
                .then(rule_a.generic.cmp(&rule_b.generic))
                .then((b.end - b.start).cmp(&(a.end - a.start)))
                .then(rule_a.id.cmp(&rule_b.id))
                .then(a.start.cmp(&b.start))
        });
        let mut kept: Vec<RegexHit> = Vec::new();
        for hit in hits {
            if !kept
                .iter()
                .any(|other| hit.start < other.end && hit.end > other.start)
            {
                kept.push(hit);
            }
        }
        kept.sort_by_key(|hit| hit.start);
        kept
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
    fn new(rules: &[CompiledRule]) -> Result<Self> {
        let mut keyword_map: HashMap<String, Vec<usize>> = HashMap::new();
        let mut always_rules = Vec::new();
        for (idx, rule) in rules.iter().enumerate() {
            if rule.rule.keywords.is_empty() {
                always_rules.push(idx);
                continue;
            }
            for keyword in &rule.rule.keywords {
                keyword_map
                    .entry(keyword.to_lowercase())
                    .or_default()
                    .push(idx);
            }
        }
        // Collect keywords and rules in a consistent order
        let mut entries: Vec<(String, Vec<usize>)> = keyword_map.into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let keywords: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
        let keyword_rules: Vec<Vec<usize>> = entries.into_iter().map(|(_, v)| v).collect();
        let ac = if keywords.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(true)
                    .match_kind(aho_corasick::MatchKind::Standard)
                    .build(&keywords)
                    .map_err(Error::Prefilter)?,
            )
        };
        Ok(Self {
            ac,
            keyword_rules,
            always_rules,
        })
    }

    fn candidates(&self, text: &str) -> Vec<usize> {
        let mut candidates: HashSet<usize> = self.always_rules.iter().copied().collect();
        let Some(ac) = &self.ac else {
            return candidates.into_iter().collect();
        };
        // Use find_overlapping_iter to catch all matches including overlapping ones
        // e.g., "sk_live_" should match both "sk" and "sk_live_" keywords
        for mat in ac.find_overlapping_iter(text) {
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
        patterns.push(Regex::new(pattern).map_err(|source| {
            Error::regex(format!("invalid allow regex pattern {pattern}"), source)
        })?);
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

fn compile_charset(validate: Option<&RuleValidate>) -> Result<Option<Regex>> {
    let Some(validate) = validate else {
        return Ok(None);
    };
    let Some(charset) = &validate.charset else {
        return Ok(None);
    };
    let pattern = format!("^[{}]+$", charset);
    Ok(Some(Regex::new(&pattern).map_err(|source| {
        Error::regex(format!("invalid charset regex {pattern}"), source)
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
    if validate.checksum.is_some() {
        // Rule loading guarantees a known algorithm and a prefix list.
        let body = validate
            .prefix
            .iter()
            .find_map(|prefix| secret.strip_prefix(prefix.as_str()));
        return body.is_some_and(crate::checksum::is_valid_suffix6);
    }
    true
}

pub fn collect_files(root: &Path, inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    walk_inputs(root, inputs, &|_| false)
}

fn walk_inputs(
    root: &Path,
    inputs: &[PathBuf],
    skip_dir: &dyn Fn(&Path) -> bool,
) -> Result<Vec<PathBuf>> {
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
        if !target.exists() {
            return Err(Error::MissingPath(target));
        }
        if target.is_dir() {
            for entry in walkdir::WalkDir::new(&target)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| !(entry.file_type().is_dir() && skip_dir(entry.path())))
                .filter_map(|entry| entry.ok())
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

/// Longest base64 token whose decoded form is still scanned (decoded size cap of 64 KiB).
const MAX_BASE64_LEN: usize = 64 * 1024 / 3 * 4;

fn is_base64_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-')
}

/// Finds runs of at least 24 base64 characters, including up to two trailing `=`.
fn base64_candidates(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut candidates = Vec::new();
    let mut idx = 0;
    while idx < bytes.len() {
        if !is_base64_char(bytes[idx]) {
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < bytes.len() && is_base64_char(bytes[idx]) {
            idx += 1;
        }
        if idx - start < 24 {
            continue;
        }
        let mut end = idx;
        while end < bytes.len() && end - idx < 2 && bytes[end] == b'=' {
            end += 1;
        }
        idx = end;
        if end - start <= MAX_BASE64_LEN {
            candidates.push((start, end));
        }
    }
    candidates
}

fn base64_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' | b'-' => 62,
        _ => 63,
    }
}

/// Decodes a standard or URL-safe base64 token. Returns the text only if it is valid UTF-8
/// and at least 90 % printable ASCII; mixed alphabets and bad lengths yield `None`.
fn decode_base64(token: &[u8]) -> Option<String> {
    let body_len = token.iter().take_while(|&&byte| byte != b'=').count();
    let (body, padding) = token.split_at(body_len);
    if body.len() % 4 == 1 || (!padding.is_empty() && (body.len() + padding.len()) % 4 != 0) {
        return None;
    }
    let standard = body.iter().any(|&byte| matches!(byte, b'+' | b'/'));
    let url_safe = body.iter().any(|&byte| matches!(byte, b'-' | b'_'));
    if standard && url_safe {
        return None;
    }
    let max_bad = body.len() * 3 / 4 / 10;
    let mut bad = 0;
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for chunk in body.chunks(4) {
        let mut acc = 0u32;
        for &byte in chunk {
            acc = acc << 6 | u32::from(base64_value(byte));
        }
        acc <<= 6 * (4 - chunk.len());
        for &byte in &acc.to_be_bytes()[1..chunk.len()] {
            if !(byte == b'\n' || byte == b'\r' || byte == b'\t' || (0x20..0x7f).contains(&byte)) {
                bad += 1;
                if bad > max_bad {
                    return None;
                }
            }
            out.push(byte);
        }
    }
    String::from_utf8(out).ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Config;
    use std::process::Command;
    use tempfile::tempdir;

    fn base_rule(pattern: &str) -> Rule {
        Rule {
            id: "test-rule".to_string(),
            name: "Test Rule".to_string(),
            severity: Severity::High,
            pattern: pattern.to_string(),
            keywords: vec!["secret_".to_string()],
            capture: 1,
            generic: false,
            validate: None,
            paths: None,
            allow: None,
        }
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("run git");
        assert!(status.success(), "git command failed: {args:?}");
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
    fn staged_scan_reads_the_index_instead_of_the_worktree() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        git(root, &["init", "-q"]);
        let path = root.join("config.txt");
        fs::write(&path, "secret_ABC123\n").expect("write staged file");
        git(root, &["add", "config.txt"]);
        fs::remove_file(&path).expect("remove worktree file");

        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector =
            Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector");
        let findings = detector.scan_staged_files(root).expect("scan staged files");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].path, "config.txt");
    }

    #[test]
    fn staged_scan_ignores_unstaged_worktree_content() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        git(root, &["init", "-q"]);
        let path = root.join("config.txt");
        fs::write(&path, "clean\n").expect("write staged file");
        git(root, &["add", "config.txt"]);
        fs::write(&path, "secret_ABC123\n").expect("write worktree file");

        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector =
            Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector");
        let findings = detector.scan_staged_files(root).expect("scan staged files");

        assert!(findings.is_empty());
    }

    #[test]
    fn tracked_scan_covers_the_full_index_while_staged_scan_does_not() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        git(root, &["init", "-q"]);
        let path = root.join("existing.txt");
        fs::write(&path, "secret_ABC123\n").expect("write tracked file");
        git(root, &["add", "existing.txt"]);
        git(
            root,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "initial",
            ],
        );
        fs::remove_file(&path).expect("remove worktree file");

        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector =
            Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector");

        assert!(detector
            .scan_staged_files(root)
            .expect("scan staged files")
            .is_empty());
        let tracked = detector
            .scan_tracked_files(root)
            .expect("scan tracked files");
        assert_eq!(tracked.len(), 1);
        assert_eq!(tracked[0].path, "existing.txt");
    }

    #[test]
    fn file_scan_propagates_read_errors() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("missing.txt");
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector =
            Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector");

        assert!(detector.scan_files(dir.path(), &[missing]).is_err());
    }

    #[test]
    fn path_scan_rejects_missing_inputs() {
        let dir = tempdir().expect("tempdir");
        assert!(collect_files(dir.path(), &[PathBuf::from("nope.txt")]).is_err());
    }

    #[test]
    fn path_scan_does_not_descend_into_ignored_directories() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        fs::create_dir_all(root.join("node_modules/pkg")).expect("create dir");
        fs::create_dir_all(root.join("src")).expect("create dir");
        fs::write(root.join("node_modules/pkg/index.js"), "secret_ABC123").expect("write");
        fs::write(root.join("src/app.js"), "clean").expect("write");

        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector =
            Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector");
        let files = detector.collect_files(root, &[]).expect("collect");

        assert_eq!(files, vec![root.join("src/app.js")]);
        assert_eq!(collect_files(root, &[]).expect("collect").len(), 2);
    }

    fn detector_with_size_limit(max_file_size: u64) -> Detector {
        let mut config = Config::default();
        config.scan.max_file_size = max_file_size;
        let filter = Filter::from_config(Some(config), Vec::new()).expect("filter");
        Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector")
    }

    #[test]
    fn files_above_the_size_limit_are_skipped_and_counted() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        git(root, &["init", "-q"]);
        let big = root.join("big.txt");
        fs::write(&big, format!("secret_ABC123 {}\n", "x".repeat(200))).expect("write");
        fs::write(root.join("small.txt"), "secret_DEF456\n").expect("write");
        git(root, &["add", "."]);

        let limited = detector_with_size_limit(100);
        let staged = limited.scan_staged_files(root).expect("scan staged");
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].path, "small.txt");
        assert_eq!(limited.skipped_large_files(), 1);
        assert!(limited.scan_files(root, &[big]).expect("scan").is_empty());
        assert_eq!(limited.skipped_large_files(), 2);

        let unlimited = detector_with_size_limit(0);
        assert_eq!(unlimited.scan_staged_files(root).expect("scan").len(), 2);
        assert_eq!(unlimited.skipped_large_files(), 0);
    }

    #[test]
    fn overlapping_rules_report_the_most_specific_one() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("config.txt");
        fs::write(&path, "key = secret_ABC123\nother = secret_XYZ789\n").expect("write");

        let mut generic = base_rule(r"key = (secret_[A-Z0-9]{6})");
        generic.id = "a-generic".to_string();
        generic.generic = true;
        let mut specific = base_rule(r"(secret_[A-Z0-9]{6})");
        specific.id = "z-specific".to_string();
        let mut weaker = base_rule(r"(secret_[A-Z0-9]{6})");
        weaker.id = "weaker".to_string();
        weaker.severity = Severity::Low;

        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector = Detector::new(vec![generic, specific, weaker], filter).expect("detector");
        for _ in 0..20 {
            let findings = detector
                .scan_files(root, std::slice::from_ref(&path))
                .expect("scan");
            let found: Vec<(&str, usize)> = findings
                .iter()
                .map(|finding| (finding.rule_id.as_str(), finding.line))
                .collect();
            assert_eq!(found, vec![("z-specific", 1), ("z-specific", 2)]);
        }
    }

    #[test]
    fn inline_marker_inside_other_text_does_not_ignore() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path();
        let path = root.join("config.txt");
        fs::write(
            &path,
            "contact = \"bob@nsight.io\"; key = \"secret_ABC123\"\n",
        )
        .expect("write");

        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let detector =
            Detector::new(vec![base_rule(r"(secret_[A-Z0-9]{6})")], filter).expect("detector");
        assert_eq!(detector.scan_files(root, &[path]).expect("scan").len(), 1);
    }

    #[test]
    fn detector_rejects_duplicate_rule_ids() {
        let rule = base_rule(r"(secret_[A-Z0-9]{6})");
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let error = Detector::new(vec![rule.clone(), rule], filter)
            .err()
            .expect("duplicate ids must fail");

        assert!(error.to_string().contains("duplicate rule id"));
    }

    #[test]
    fn detector_rejects_missing_capture_groups() {
        let mut rule = base_rule(r"secret_[A-Z0-9]{6}");
        rule.capture = 1;
        let filter = Filter::from_config(None, Vec::new()).expect("filter");
        let error = Detector::new(vec![rule], filter)
            .err()
            .expect("missing capture group must fail");

        assert!(error.to_string().contains("capture group 1 does not exist"));
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
