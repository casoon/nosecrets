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

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .expect("run git");
    assert!(status.success(), "git {args:?}");
}

fn git_repo() -> TempDir {
    let dir = tempdir().expect("tempdir");
    git(dir.path(), &["init", "-q"]);
    dir
}

fn hook(dir: &Path, input: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_nosecrets"))
        .args(["hook", "claude-code"])
        .current_dir(dir)
        .env(
            "GIT_CEILING_DIRECTORIES",
            dir.parent().expect("temp dir has a parent"),
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nosecrets");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn bash_input(cwd: &Path, command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": cwd,
    })
    .to_string()
}

fn assert_blocked(output: &Output) {
    assert_eq!(output.status.code(), Some(EXIT_ERROR), "{}", stderr(output));
    let err = stderr(output);
    assert!(err.contains("github-pat"));
    assert!(err.contains("nsi_"));
    assert!(err.contains("nosecrets ignore"));
    assert!(!err.contains(&fake_token()));
    assert!(stdout(output).is_empty());
}

fn staged_token_repo() -> TempDir {
    let dir = git_repo();
    fs::write(
        dir.path().join("config.py"),
        format!("token = \"{}\"\n", fake_token()),
    )
    .expect("write");
    git(dir.path(), &["add", "config.py"]);
    dir
}

fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let acc = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(acc >> (18 - 6 * i) & 63) as usize] as char);
        }
        out.push_str(&"=".repeat(3 - chunk.len()));
    }
    out
}

fn dir_with_base64_finding() -> TempDir {
    let dir = tempdir().expect("tempdir");
    fs::write(
        dir.path().join("secret.yaml"),
        format!(
            "data:\n  token: {}\n",
            base64_standard(fake_token().as_bytes())
        ),
    )
    .expect("write");
    dir
}

#[test]
fn hook_ignores_other_tools() {
    let dir = staged_token_repo();
    let input = serde_json::json!({
        "tool_name": "Write",
        "tool_input": { "command": "git commit -m x" },
        "cwd": dir.path(),
    })
    .to_string();
    let output = hook(dir.path(), &input);
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stderr(&output).is_empty());
}

#[test]
fn hook_does_not_scan_other_commands() {
    // The staged token would block a commit; `git status` must pass without a scan.
    let dir = staged_token_repo();
    for command in ["git status", "git commit-tree HEAD", "echo \"git commit\""] {
        let output = hook(dir.path(), &bash_input(dir.path(), command));
        assert_eq!(output.status.code(), Some(EXIT_OK), "{command}");
        assert!(stderr(&output).is_empty(), "{command}");
    }
}

#[test]
fn hook_blocks_commit_with_staged_secret() {
    let dir = staged_token_repo();
    let output = hook(dir.path(), &bash_input(dir.path(), "git commit -m x"));
    assert_blocked(&output);
}

#[test]
fn hook_allows_commit_with_clean_stage() {
    let dir = git_repo();
    fs::write(dir.path().join("main.py"), "print(1)\n").expect("write");
    git(dir.path(), &["add", "main.py"]);
    let output = hook(dir.path(), &bash_input(dir.path(), "git commit -m x"));
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stderr(&output).is_empty());
}

#[test]
fn hook_warns_and_allows_on_invalid_json() {
    let dir = tempdir().expect("tempdir");
    let output = hook(dir.path(), "not json");
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stderr(&output).contains("warning"));
}

#[test]
fn hook_warns_and_allows_outside_a_repository() {
    let dir = tempdir().expect("tempdir");
    let output = hook(dir.path(), &bash_input(dir.path(), "git commit -m x"));
    assert_eq!(output.status.code(), Some(EXIT_OK));
    assert!(stderr(&output).contains("warning"));
}

/// A path as it appears in a shell command: the hook reads the command like Bash does, where a
/// backslash is an escape character, so Windows paths are written with forward slashes.
fn shell_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

#[test]
fn hook_follows_git_dash_c() {
    let repo = staged_token_repo();
    let elsewhere = tempdir().expect("tempdir");
    let command = format!("git -C {} commit -m x", shell_path(repo.path()));
    let output = hook(elsewhere.path(), &bash_input(elsewhere.path(), &command));
    assert_blocked(&output);
}

#[test]
fn hook_follows_cd_in_a_chain() {
    let repo = staged_token_repo();
    let other = tempdir().expect("tempdir");
    let command = format!("cd {} && git commit -m x", shell_path(repo.path()));
    let output = hook(other.path(), &bash_input(other.path(), &command));
    assert_blocked(&output);
}

#[test]
fn hook_scans_unstaged_changes_for_commit_all() {
    let dir = git_repo();
    fs::write(dir.path().join("config.py"), "token = \"none\"\n").expect("write");
    git(dir.path(), &["add", "config.py"]);
    git(
        dir.path(),
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    );
    fs::write(
        dir.path().join("config.py"),
        format!("token = \"{}\"\n", fake_token()),
    )
    .expect("write");

    let plain = hook(dir.path(), &bash_input(dir.path(), "git commit -m x"));
    assert_eq!(plain.status.code(), Some(EXIT_OK));
    for command in ["git commit -am x", "git commit --all -m x"] {
        let output = hook(dir.path(), &bash_input(dir.path(), command));
        assert_blocked(&output);
    }
}

#[test]
fn hook_scans_files_added_earlier_in_the_chain() {
    let dir = git_repo();
    fs::write(
        dir.path().join("config.py"),
        format!("token = \"{}\"\n", fake_token()),
    )
    .expect("write");
    let command = "git add . && git commit -m x";
    let output = hook(dir.path(), &bash_input(dir.path(), command));
    assert_blocked(&output);
}

#[test]
fn base64_finding_is_marked_in_text_and_json_only_when_decoded() {
    let dir = dir_with_base64_finding();
    let text = nosecrets(dir.path(), &["scan", "."]);
    assert_eq!(text.status.code(), Some(EXIT_FINDINGS));
    assert!(
        stdout(&text).contains("secret.yaml:2:10"),
        "{}",
        stdout(&text)
    );
    assert!(stdout(&text)
        .trim_end()
        .lines()
        .next()
        .unwrap()
        .ends_with("(base64)"));
    let json = nosecrets(dir.path(), &["scan", "--format", "json", "."]);
    assert!(stdout(&json).contains("\"encoding\": \"base64\""));

    let plain = dir_with_finding();
    let json = nosecrets(plain.path(), &["scan", "--format", "json", "."]);
    assert!(!stdout(&json).contains("encoding"));
}

#[test]
fn decode_section_can_disable_base64() {
    let dir = dir_with_base64_finding();
    fs::write(
        dir.path().join(".nosecrets.toml"),
        "[decode]\nbase64 = false\n",
    )
    .expect("write");
    let output = nosecrets(dir.path(), &["scan", "."]);
    assert_eq!(output.status.code(), Some(EXIT_OK), "{}", stdout(&output));
}
