use globset::{Glob, GlobMatcher, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub ignore: IgnoreConfig,
    #[serde(default)]
    pub allow: AllowConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct IgnoreConfig {
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct AllowConfig {
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub values: Vec<String>,
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
}

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("failed to read {path}: {error}")]
    Read {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("failed to parse {path}: {error}")]
    Parse {
        path: PathBuf,
        #[source]
        error: toml::de::Error,
    },
    #[error("invalid glob pattern {pattern}: {error}")]
    Glob {
        pattern: String,
        #[source]
        error: globset::Error,
    },
    #[error("invalid regex pattern {pattern}: {error}")]
    Regex {
        pattern: String,
        #[source]
        error: regex::Error,
    },
}

impl Config {
    pub fn load_from_dir(dir: &Path) -> Result<Option<Self>, FilterError> {
        let path = dir.join(".nosecrets.toml");
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path).map_err(|error| FilterError::Read {
            path: path.clone(),
            error,
        })?;
        let config = toml::from_str(&content).map_err(|error| FilterError::Parse {
            path: path.clone(),
            error,
        })?;
        Ok(Some(config))
    }
}

pub fn load_ignore_file(path: &Path) -> Result<Vec<IgnoreEntry>, FilterError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).map_err(|error| FilterError::Read {
        path: path.to_path_buf(),
        error,
    })?;
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.splitn(2, ':');
        let fingerprint = parts.next().unwrap().trim().to_string();
        let matcher = parts
            .next()
            .map(|glob| glob.trim())
            .filter(|glob| !glob.is_empty())
            .map(|glob| {
                let normalized = normalize_glob_pattern(glob);
                Glob::new(&normalized)
                    .map(|g| g.compile_matcher())
                    .map_err(|error| FilterError::Glob {
                        pattern: normalized.clone(),
                        error,
                    })
            })
            .transpose()?;
        entries.push(IgnoreEntry {
            fingerprint,
            matcher,
        });
    }
    Ok(entries)
}

impl Filter {
    pub fn from_config(
        config: Option<Config>,
        ignore_entries: Vec<IgnoreEntry>,
    ) -> Result<Self, FilterError> {
        let config = config.unwrap_or_default();
        let ignore_paths = if config.ignore.paths.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for pattern in &config.ignore.paths {
                let normalized = normalize_glob_pattern(pattern);
                let glob = Glob::new(&normalized).map_err(|error| FilterError::Glob {
                    pattern: normalized.clone(),
                    error,
                })?;
                builder.add(glob);
            }
            Some(builder.build().map_err(|error| FilterError::Glob {
                pattern: "<globset>".to_string(),
                error,
            })?)
        };

        let mut allow_patterns = Vec::new();
        for pattern in &config.allow.patterns {
            let regex = Regex::new(pattern).map_err(|error| FilterError::Regex {
                pattern: pattern.clone(),
                error,
            })?;
            allow_patterns.push(regex);
        }
        let allow_values = config.allow.values.into_iter().collect();

        Ok(Self {
            ignore_paths,
            allow_patterns,
            allow_values,
            ignore_entries,
        })
    }

    pub fn is_path_ignored(&self, path: &Path) -> bool {
        let Some(globset) = &self.ignore_paths else {
            return false;
        };
        let normalized = normalize_path(path);
        globset.is_match(normalized)
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
        line.contains("@nosecrets-ignore") || line.contains("@nsi")
    }
}

pub fn normalize_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    raw.trim_start_matches("./").to_string()
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
    fn inline_ignore_detection() {
        assert!(Filter::is_inline_ignored(
            "key = \"secret\" # @nosecrets-ignore"
        ));
        assert!(Filter::is_inline_ignored("// @nsi test"));
        assert!(!Filter::is_inline_ignored("no ignore here"));
    }
}
