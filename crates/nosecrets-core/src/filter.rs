use globset::{Glob, GlobMatcher, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use crate::error::{Error, Result};

/// Inline ignore markers count only as standalone tokens: after the start of the line,
/// whitespace or a comment opener, and not followed by a word character.
static INLINE_IGNORE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[\s#/*;!-])(?:@nosecrets-ignore|@nsi|gitleaks:allow)(?:$|\W)")
        .expect("inline ignore regex")
});

const DEFAULT_IGNORE_PATHS: &[&str] = &[
    "**/.git/**",
    "**/node_modules/**",
    "**/.pnpm-store/**",
    "**/.yarn/**",
    "**/.astro/**",
    "**/.wrangler/**",
    "**/dist/**",
    "**/build/**",
    "**/.next/**",
    "**/.svelte-kit/**",
    "**/coverage/**",
    "**/target/**",
    "**/playwright-report/**",
    "**/test-results/**",
];

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub ignore: IgnoreConfig,
    #[serde(default)]
    pub allow: AllowConfig,
    #[serde(default)]
    pub entropy: EntropyConfig,
    #[serde(default)]
    pub scan: ScanConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Files larger than this many bytes are skipped; `0` disables the limit.
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: default_max_file_size(),
        }
    }
}

fn default_max_file_size() -> u64 {
    5 * 1024 * 1024
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct AllowConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct EntropyConfig {
    #[serde(default = "entropy_default_enabled")]
    pub enabled: bool,
    #[serde(default = "entropy_default_min_length")]
    pub min_length: usize,
    #[serde(default = "entropy_default_threshold")]
    pub threshold: f64,
    #[serde(default = "entropy_default_require_context")]
    pub require_context: bool,
    #[serde(default)]
    pub allow: EntropyAllowConfig,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: entropy_default_enabled(),
            min_length: entropy_default_min_length(),
            threshold: entropy_default_threshold(),
            require_context: entropy_default_require_context(),
            allow: EntropyAllowConfig::default(),
        }
    }
}

fn entropy_default_enabled() -> bool {
    true
}

fn entropy_default_min_length() -> usize {
    20
}

fn entropy_default_threshold() -> f64 {
    4.2
}

fn entropy_default_require_context() -> bool {
    true
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct EntropyAllowConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug)]
pub struct IgnoreEntry {
    pub fingerprint: String,
    pub matcher: Option<GlobMatcher>,
}

#[derive(Debug)]
pub struct Filter {
    ignore_paths: Option<GlobSet>,
    allow_patterns: Vec<Regex>,
    allow_values: HashSet<String>,
    ignore_entries: Vec<IgnoreEntry>,
    max_file_size: u64,
}

impl Config {
    pub fn load_from_dir(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(".nosecrets.toml");
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path).map_err(|source| read_error(&path, source))?;
        let config = toml::from_str(&content).map_err(|source| Error::ParseConfig {
            path: path.clone(),
            source,
        })?;
        Ok(Some(config))
    }
}

pub fn load_ignore_file(path: &Path) -> Result<Vec<IgnoreEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(|source| read_error(path, source))?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (fingerprint, path_glob) = match trimmed.split_once(':') {
            Some((fingerprint, glob)) => (fingerprint, Some(glob)),
            None => (trimmed, None),
        };
        let matcher = path_glob
            .map(|glob| glob.trim())
            .filter(|glob| !glob.is_empty())
            .map(|glob| {
                let normalized = normalize_glob_pattern(glob);
                Glob::new(&normalized)
                    .map(|g| g.compile_matcher())
                    .map_err(|source| Error::Glob {
                        pattern: normalized.clone(),
                        source,
                    })
            })
            .transpose()?;
        entries.push(IgnoreEntry {
            fingerprint: fingerprint.trim().to_string(),
            matcher,
        });
    }
    Ok(entries)
}

impl Filter {
    pub fn from_config(config: Option<Config>, ignore_entries: Vec<IgnoreEntry>) -> Result<Self> {
        let config = config.unwrap_or_default();
        let mut all_ignore_paths: Vec<String> = DEFAULT_IGNORE_PATHS
            .iter()
            .map(|pattern| (*pattern).to_string())
            .collect();
        all_ignore_paths.extend(config.ignore.paths.iter().cloned());

        let ignore_paths = build_globset(&all_ignore_paths)?;

        let mut allow_patterns = Vec::new();
        for pattern in &config.allow.patterns {
            let regex = Regex::new(pattern).map_err(|source| {
                Error::regex(format!("invalid regex pattern {pattern}"), source)
            })?;
            allow_patterns.push(regex);
        }
        let allow_values = config.allow.values.into_iter().collect();

        Ok(Self {
            ignore_paths,
            allow_patterns,
            allow_values,
            ignore_entries,
            max_file_size: config.scan.max_file_size,
        })
    }

    pub fn is_path_ignored(&self, path: &Path) -> bool {
        let Some(globset) = &self.ignore_paths else {
            return false;
        };
        let normalized = normalize_path(path);
        globset.is_match(normalized)
    }

    /// True if everything below the directory is ignored, so a walk need not descend into it.
    pub fn is_dir_ignored(&self, dir: &Path) -> bool {
        self.is_path_ignored(&dir.join("\u{1}nosecrets-probe\u{1}"))
    }

    /// Size limit in bytes for scanned files; `None` when the limit is disabled.
    pub fn max_file_size(&self) -> Option<u64> {
        (self.max_file_size > 0).then_some(self.max_file_size)
    }

    pub fn is_value_allowed(&self, value: &str) -> bool {
        if self.allow_values.contains(value) {
            return true;
        }
        self.allow_patterns
            .iter()
            .any(|regex| regex.is_match(value))
    }

    pub fn is_fingerprint_ignored(&self, fingerprint: &str, path: &Path) -> bool {
        let normalized = normalize_path(path);
        self.ignore_entries.iter().any(|entry| {
            if entry.fingerprint != fingerprint {
                return false;
            }
            match &entry.matcher {
                Some(matcher) => matcher.is_match(&normalized),
                None => true,
            }
        })
    }

    pub fn is_inline_ignored(line: &str) -> bool {
        INLINE_IGNORE.is_match(line)
    }
}

pub fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    raw.trim_start_matches("./").to_string()
}

fn read_error(path: &Path, source: std::io::Error) -> Error {
    Error::io(format!("failed to read {}", path.display()), source)
}

/// Compiles glob patterns into one set; `None` for an empty list.
pub(crate) fn build_globset(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let normalized = normalize_glob_pattern(pattern);
        let glob = Glob::new(&normalized).map_err(|source| Error::Glob {
            pattern: normalized.clone(),
            source,
        })?;
        builder.add(glob);
    }
    let set = builder.build().map_err(|source| Error::Glob {
        pattern: "<globset>".to_string(),
        source,
    })?;
    Ok(Some(set))
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
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn ignore_paths_match_trailing_slash() {
        let mut config = Config::default();
        config.ignore.paths = vec!["vendor/".to_string()];
        let filter = Filter::from_config(Some(config), Vec::new()).expect("build filter");
        assert!(filter.is_path_ignored(Path::new("vendor/lib.rs")));
        assert!(!filter.is_path_ignored(Path::new("src/lib.rs")));
    }

    #[test]
    fn allow_values_and_patterns() {
        let mut config = Config::default();
        config.allow.values = vec!["ALLOW_ME".to_string()];
        config.allow.patterns = vec!["^test_.*$".to_string()];
        let filter = Filter::from_config(Some(config), Vec::new()).expect("build filter");
        assert!(filter.is_value_allowed("ALLOW_ME"));
        assert!(filter.is_value_allowed("test_value"));
        assert!(!filter.is_value_allowed("deny"));
    }

    #[test]
    fn ignore_file_with_path_matcher() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(".nosecretsignore");
        fs::write(&path, "nsi_123:src/**\n").expect("write ignore");
        let entries = load_ignore_file(&path).expect("load ignore");
        let filter = Filter::from_config(None, entries).expect("build filter");
        assert!(filter.is_fingerprint_ignored("nsi_123", Path::new("src/main.rs")));
        assert!(!filter.is_fingerprint_ignored("nsi_123", Path::new("tests/main.rs")));
    }

    #[test]
    fn ignore_file_accepts_fingerprint_without_path() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(".nosecretsignore");
        fs::write(&path, "nsi_123\n").expect("write ignore");
        let entries = load_ignore_file(&path).expect("load ignore");
        let filter = Filter::from_config(None, entries).expect("build filter");

        assert!(filter.is_fingerprint_ignored("nsi_123", Path::new("any/path")));
    }

    #[test]
    fn inline_ignore_detection() {
        assert!(Filter::is_inline_ignored(
            "key = \"secret\" # @nosecrets-ignore"
        ));
        assert!(Filter::is_inline_ignored("// @nsi test"));
        assert!(Filter::is_inline_ignored("x = 1 # @nsi"));
        assert!(Filter::is_inline_ignored("@nsi"));
        assert!(Filter::is_inline_ignored("x = 1; /* @nosecrets-ignore */"));
        assert!(Filter::is_inline_ignored("<!--@nsi-->"));
        assert!(Filter::is_inline_ignored("key: value # gitleaks:allow"));
        assert!(!Filter::is_inline_ignored("no ignore here"));
    }

    #[test]
    fn inline_ignore_requires_a_standalone_marker() {
        assert!(!Filter::is_inline_ignored("contact = \"bob@nsight.io\""));
        assert!(!Filter::is_inline_ignored("mail user@nsi.example"));
        assert!(!Filter::is_inline_ignored("foo@nsiX"));
        assert!(!Filter::is_inline_ignored("# @nsight"));
        assert!(!Filter::is_inline_ignored("nogitleaks:allowed"));
    }

    #[test]
    fn unknown_config_keys_are_rejected() {
        let dir = tempdir().expect("tempdir");
        fs::write(
            dir.path().join(".nosecrets.toml"),
            "[entropy]\ntreshold = 9.9\n",
        )
        .expect("write config");
        let error = Config::load_from_dir(dir.path()).expect_err("must fail");
        assert!(format!("{error:?}").contains("treshold"));
    }

    #[test]
    fn ignored_directories_are_recognised() {
        let mut config = Config::default();
        config.ignore.paths = vec!["vendor/".to_string(), "gen/*.js".to_string()];
        let filter = Filter::from_config(Some(config), Vec::new()).expect("build filter");
        assert!(filter.is_dir_ignored(Path::new("vendor")));
        assert!(filter.is_dir_ignored(Path::new("web/node_modules")));
        assert!(!filter.is_dir_ignored(Path::new("gen")));
        assert!(!filter.is_dir_ignored(Path::new("src")));
    }

    #[test]
    fn default_ignore_paths_skip_common_build_and_dependency_dirs() {
        let filter = Filter::from_config(None, Vec::new()).expect("build filter");
        assert!(filter.is_path_ignored(Path::new("node_modules/pkg/index.js")));
        assert!(filter.is_path_ignored(Path::new(".wrangler/tmp/worker.js")));
        assert!(filter.is_path_ignored(Path::new("dist/client/index.html")));
        assert!(filter.is_path_ignored(Path::new(".astro/types.d.ts")));
        assert!(filter.is_path_ignored(Path::new("playwright-report/index.html")));
        assert!(filter.is_path_ignored(Path::new("test-results/run/output.json")));
        assert!(!filter.is_path_ignored(Path::new("src/pages/index.astro")));
    }
}
