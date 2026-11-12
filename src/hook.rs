//! `nosecrets hook claude-code`: a Claude Code `PreToolUse` hook that blocks `git commit`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use nosecrets_core::{discover_repo_root, Finding, Report};

use crate::build_detector;

/// Exit code Claude Code treats as "block the tool call and show stderr to the model".
const EXIT_BLOCK: i32 = 2;

/// One `git commit` found in a shell command.
#[derive(Debug, PartialEq, Eq)]
struct Commit {
    /// Directory the commit runs in, after `cd` and `git -C`; may be relative to the hook `cwd`.
    dir: PathBuf,
    /// `-a`/`--all`: modified tracked files are staged by the commit itself.
    all: bool,
    /// A `git add` precedes the commit in the same command, so its target is not staged yet.
    add_before: bool,
}

/// Entry point. Internal errors never block the agent: they warn on stderr and exit 0.
pub(crate) fn run_claude_code() -> i32 {
    match check() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("nosecrets hook: warning: commit not checked: {error:#}");
            0
        }
    }
}

fn check() -> Result<i32> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("failed to read stdin")?;
    let value: serde_json::Value =
        serde_json::from_str(&input).context("stdin is not valid hook JSON")?;

    if value["tool_name"].as_str() != Some("Bash") {
        return Ok(0);
    }
    let Some(command) = value["tool_input"]["command"].as_str() else {
        return Ok(0);
    };
    let commits = find_commits(command, Path::new(value["cwd"].as_str().unwrap_or(".")));
    if commits.is_empty() {
        return Ok(0);
    }

    let mut findings = Vec::new();
    for commit in &commits {
        findings.extend(scan_commit(commit)?);
    }
    let report = Report::new(findings);
    let blocking: Vec<&Finding> = report
        .findings()
        .iter()
        .filter(|finding| finding.severity.blocks())
        .collect();
    if blocking.is_empty() {
        return Ok(0);
    }

    eprintln!("nosecrets: commit blocked, the content to be committed contains secrets:");
    for finding in blocking {
        eprintln!(
            "  {}:{}:{} {} ({}) {}  preview: {}",
            finding.path,
            finding.line,
            finding.column,
            finding.rule_name,
            finding.rule_id,
            finding.fingerprint,
            finding.preview
        );
    }
    eprintln!(
        "Remove the secret from the file and stage the change again. If a finding is a false \
         positive or a known value, run `nosecrets ignore <fingerprint>` (add `--path <glob>` \
         to scope it) or add an `@nsi` marker to the line, then commit again."
    );
    Ok(EXIT_BLOCK)
}

fn scan_commit(commit: &Commit) -> Result<Vec<Finding>> {
    let Some(repo_root) = discover_repo_root(&commit.dir)? else {
        return Err(anyhow!(
            "{} is not in a git repository",
            commit.dir.display()
        ));
    };
    let detector = build_detector(&repo_root, &[])?;
    let mut findings = detector.scan_staged_files(&repo_root)?;

    if commit.all || commit.add_before {
        let mut files = git_list(
            &repo_root,
            &["diff", "--name-only", "-z", "--diff-filter=ACMR"],
        )?;
        if commit.add_before {
            files.extend(git_list(
                &repo_root,
                &["ls-files", "-z", "--others", "--exclude-standard"],
            )?);
        }
        let files: Vec<PathBuf> = files
            .into_iter()
            .map(|file| repo_root.join(file))
            .filter(|path| path.is_file())
            .collect();
        findings.extend(detector.scan_files(&repo_root, &files)?);
    }
    Ok(findings)
}

fn git_list(repo_root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .context("failed to execute git")?;
    if !output.status.success() {
        return Err(anyhow!("git {} failed", args[0]));
    }
    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .collect())
}

/// Splits a shell command into simple commands made of words. Quotes group text into one word
/// (so `echo "git commit"` stays a single word of `echo`); `&&`, `||`, `;`, `|`, `&`, newlines
/// and parentheses end a command. Substitutions, heredocs and `bash -c '...'` are not looked into.
fn split_commands(command: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for q in chars.by_ref() {
                    if q == '\'' {
                        break;
                    }
                    word.push(q);
                }
            }
            '"' => {
                in_word = true;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => break,
                        '\\' => {
                            if let Some(next) = chars.next() {
                                word.push(next);
                            }
                        }
                        _ => word.push(q),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(next) = chars.next() {
                    if next != '\n' {
                        word.push(next);
                    }
                }
            }
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '&' | '|' | ';' | '\n' | '(' | ')' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
                if !words.is_empty() {
                    commands.push(std::mem::take(&mut words));
                }
            }
            _ => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    if !words.is_empty() {
        commands.push(words);
    }
    commands
}

/// Global git options that take a separate value argument.
const GIT_OPTIONS_WITH_VALUE: &[&str] = &["-C", "-c", "--git-dir", "--work-tree", "--namespace"];
/// Short options of `git commit` that take a value, which may follow in the same word (`-am`).
const COMMIT_SHORT_WITH_VALUE: &str = "mFcCtS";

fn find_commits(command: &str, cwd: &Path) -> Vec<Commit> {
    let mut commits = Vec::new();
    let mut dir = cwd.to_path_buf();
    let mut add_before = false;
    for words in split_commands(command) {
        // Leading `VAR=value` assignments.
        let mut words = words
            .iter()
            .skip_while(|word| word.contains('=') && !word.starts_with('-'))
            .map(String::as_str);
        let Some(program) = words.next() else {
            continue;
        };
        if program == "cd" {
            if let Some(target) = words.next() {
                dir = dir.join(target);
            }
            continue;
        }
        if program != "git" && !program.ends_with("/git") {
            continue;
        }

        let mut git_dir = dir.clone();
        let mut subcommand = None;
        while let Some(word) = words.next() {
            if word == "-C" {
                if let Some(target) = words.next() {
                    git_dir = git_dir.join(target);
                }
            } else if GIT_OPTIONS_WITH_VALUE.contains(&word) {
                words.next();
            } else if word.starts_with('-') {
                // Option without a separate value, e.g. `--no-pager` or `--git-dir=x`.
            } else {
                subcommand = Some(word);
                break;
            }
        }
        match subcommand {
            Some("add") => add_before = true,
            Some("commit") => {
                let mut all = false;
                for word in words {
                    if word == "--" {
                        break;
                    }
                    if word == "--all" {
                        all = true;
                    } else if word.starts_with('-') && !word.starts_with("--") {
                        for flag in word.chars().skip(1) {
                            if flag == 'a' {
                                all = true;
                            }
                            if COMMIT_SHORT_WITH_VALUE.contains(flag) || flag == 'a' {
                                break;
                            }
                        }
                    }
                }
                commits.push(Commit {
                    dir: git_dir,
                    all,
                    add_before,
                });
            }
            _ => {}
        }
    }
    commits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commits(command: &str) -> Vec<Commit> {
        find_commits(command, Path::new("/w"))
    }

    fn commit(dir: &str, all: bool, add_before: bool) -> Commit {
        Commit {
            dir: PathBuf::from(dir),
            all,
            add_before,
        }
    }

    #[test]
    fn detects_plain_and_option_forms() {
        assert_eq!(commits("git commit -m x"), [commit("/w", false, false)]);
        assert_eq!(commits("git commit -am 'x y'"), [commit("/w", true, false)]);
        assert_eq!(
            commits("git commit --all -m x"),
            [commit("/w", true, false)]
        );
        assert_eq!(
            commits("git -C sub commit -m x"),
            [commit("/w/sub", false, false)]
        );
        assert_eq!(
            commits("git -c user.name=a --no-pager commit"),
            [commit("/w", false, false)]
        );
        assert_eq!(commits("GIT_X=1 git commit"), [commit("/w", false, false)]);
    }

    #[test]
    fn follows_compound_commands() {
        assert_eq!(
            commits("cd sub && git commit -m x"),
            [commit("/w/sub", false, false)]
        );
        assert_eq!(
            commits("git add . && git commit -m x"),
            [commit("/w", false, true)]
        );
        assert_eq!(commits("make; git commit"), [commit("/w", false, false)]);
    }

    #[test]
    fn ignores_look_alikes() {
        for command in [
            "git status",
            "git commit-tree HEAD^{tree}",
            "git log --grep commit",
            "echo \"git commit\"",
            "echo 'git commit -am x'",
            "gitk commit",
        ] {
            assert!(commits(command).is_empty(), "{command}");
        }
    }

    #[test]
    fn message_text_does_not_count_as_all() {
        assert_eq!(
            commits("git commit -m 'fix -a bug'"),
            [commit("/w", false, false)]
        );
    }
}
