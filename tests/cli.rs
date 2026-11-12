//! Runs the built binary and checks exit codes and output streams.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::{tempdir, TempDir};

const EXIT_OK: i32 = 0;
const EXIT_FINDINGS: i32 = 1;
const EXIT_ERROR: i32 = 2;

fn nosecrets(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nosecrets"))
        .args(args)
        .current_dir(dir)
        // Keep the test independent of a repository the temp dir may live in.
        .env(
            "GIT_CEILING_DIRECTORIES",
            dir.parent().expect("temp dir has a parent"),
        )
        .output()
        .expect("run nosecrets")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A fake GitHub token, assembled at runtime so the source file holds no match.
fn fake_token() -> String {
    ["ghp_", "1234567890abcdefghijklmnopqrstuvwxyz"].concat()
}

fn dir_with_finding() -> TempDir {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("config.py"),
        format!("token = \"{}\"\n", fake_token()),
    )
    .expect("write");
    dir
}

#[test]
fn clean_directory_exits_zero() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("main.py"), "print(1)\n").expect("write");
    let output = nosecrets(dir.path(), &["scan", "."]);
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stdout(&output).contains("No secrets found"));
}

#[test]
fn finding_exits_one_and_never_prints_the_secret() {
    let dir = dir_with_finding();
    let output = nosecrets(dir.path(), &["scan", "."]);
    assert_eq!(output.status.code(), Some(EXIT_FINDINGS));
    assert!(stdout(&output).contains("github-pat"));
    assert!(!stdout(&output).contains(&fake_token()));
    // Piped output carries no colour codes.
    assert!(!stdout(&output).contains('\u{1b}'));
}

#[test]
fn dry_run_reports_but_exits_zero() {
    let dir = dir_with_finding();
    let output = nosecrets(dir.path(), &["scan", "--dry-run", "."]);
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stdout(&output).contains("github-pat"));
}

#[test]
fn json_output_is_valid_json() {
    let dir = dir_with_finding();
    let output = nosecrets(dir.path(), &["scan", "--format", "json", "."]);
    assert_eq!(output.status.code(), Some(EXIT_FINDINGS));
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(findings[0]["rule_id"], "github-pat");
    assert_eq!(findings[0]["path"], "config.py");
}

#[test]
fn sarif_output_is_valid_and_never_prints_the_secret() {
    let dir = dir_with_finding();
    let output = nosecrets(dir.path(), &["scan", "--format", "sarif", "."]);
    assert_eq!(output.status.code(), Some(EXIT_FINDINGS));
    let sarif: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(sarif["version"], "2.1.0");
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "github-pat");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "config.py"
    );
    assert!(!stdout(&output).contains(&fake_token()));
}

#[test]
fn missing_path_is_an_error() {
    let dir = tempdir().expect("tempdir");
    let output = nosecrets(dir.path(), &["scan", "nope.txt"]);
    assert_eq!(output.status.code(), Some(EXIT_ERROR));
    assert!(stderr(&output).contains("nope.txt"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn invalid_config_is_an_error_even_with_dry_run() {
    let dir = dir_with_finding();
    fs::write(
        dir.path().join(".nosecrets.toml"),
        "[entropy]\ntreshold = 9.9\n",
    )
    .expect("write");
    let output = nosecrets(dir.path(), &["scan", "--dry-run", "."]);
    assert_eq!(output.status.code(), Some(EXIT_ERROR));
    assert!(stderr(&output).contains("treshold"));
}

#[test]
fn staged_scan_outside_a_repository_is_an_error() {
    let dir = tempdir().expect("tempdir");
    let output = nosecrets(dir.path(), &["scan", "--staged"]);
    assert_eq!(output.status.code(), Some(EXIT_ERROR));
    assert!(stderr(&output).contains("git repository"));
}

#[test]
fn oversized_files_are_reported_on_stderr() {
    let dir = dir_with_finding();
    fs::write(
        dir.path().join(".nosecrets.toml"),
        "[scan]\nmax_file_size = 10\n",
    )
    .expect("write");
    let output = nosecrets(dir.path(), &["scan", "config.py"]);
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stderr(&output).contains("skipped 1 file(s)"));
}
