use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong in the library. The underlying cause, where there is one,
/// is available through [`std::error::Error::source`] and is not repeated in the message.
#[derive(Debug, Error)]
pub enum Error {
    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path}")]
    ParseConfig {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to parse rules from {file}")]
    ParseRules {
        file: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("invalid rule {id:?} in {file}: {reason}")]
    InvalidRule {
        file: String,
        id: String,
        reason: &'static str,
    },
    #[error("duplicate rule id {0}")]
    DuplicateRule(String),
    #[error("capture group {capture} does not exist for rule {id}")]
    MissingCapture { id: String, capture: usize },
    #[error("invalid glob pattern {pattern}")]
    Glob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("{context}")]
    Regex {
        context: String,
        #[source]
        source: regex::Error,
    },
    #[error("failed to build keyword prefilter")]
    Prefilter(#[source] aho_corasick::BuildError),
    #[error("path does not exist: {0}")]
    MissingPath(PathBuf),
    #[error("{0}")]
    Git(String),
    #[error("failed to serialize json")]
    Json(#[source] serde_json::Error),
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn regex(context: impl Into<String>, source: regex::Error) -> Self {
        Self::Regex {
            context: context.into(),
            source,
        }
    }
}
