//! Scanning engine of the `nosecrets` secret scanner: rules, filters, detection and reporting.

mod checksum;
mod detector;
pub mod entropy;
mod error;
mod filter;
mod git;
mod report;
mod rules;

pub use detector::{collect_files, Detector};
pub use error::{Error, Result};
pub use filter::{
    load_ignore_file, normalize_path, AllowConfig, Config, DecodeConfig, EntropyAllowConfig,
    EntropyConfig, Filter, IgnoreConfig, IgnoreEntry, ScanConfig,
};
pub use git::discover_repo_root;
pub use report::{fingerprint_secret, mask_secret, Finding, Report};
pub use rules::{
    load_builtin_rules, parse_rules, Rule, RuleAllow, RulePaths, RuleValidate, Severity,
};
