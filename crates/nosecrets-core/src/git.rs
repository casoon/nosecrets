use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::thread::JoinHandle;

use crate::error::{Error, Result};

fn git_error(message: impl Into<String>) -> Error {
    Error::Git(message.into())
}

fn read_error(source: std::io::Error) -> Error {
    Error::io("failed to read git output", source)
}

pub fn discover_repo_root(start: &Path) -> Result<Option<PathBuf>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(start)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|source| Error::io("failed to execute git", source))?;
    if !output.status.success() {
        return Ok(None);
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|_| git_error("git returned a non-UTF-8 repository path"))?;
    Ok(Some(PathBuf::from(path.trim_end_matches(['\r', '\n']))))
}

pub(crate) struct GitBlob {
    pub(crate) path: PathBuf,
    object_id: String,
    pub(crate) content: Vec<u8>,
}

pub(crate) fn list_staged_blobs(repo_root: &Path) -> Result<Vec<GitBlob>> {
    let output = run_git(
        repo_root,
        &[
            "diff",
            "--cached",
            "--raw",
            "--no-abbrev",
            "-z",
            "--diff-filter=ACMR",
        ],
        "git diff --cached",
    )?;

    let mut fields = output.stdout.split(|byte| *byte == 0);
    let mut blobs = Vec::new();
    while let Some(header) = fields.next() {
        if header.is_empty() {
            break;
        }
        let header =
            std::str::from_utf8(header).map_err(|_| git_error("invalid git diff metadata"))?;
        let parts: Vec<&str> = header.split_ascii_whitespace().collect();
        if parts.len() != 5 || !parts[0].starts_with(':') {
            return Err(git_error(format!("unexpected git diff metadata: {header}")));
        }
        let new_mode = parts[1];
        let object_id = parts[3];
        let status = parts[4]
            .as_bytes()
            .first()
            .copied()
            .ok_or_else(|| git_error("missing git diff status"))?;
        let first_path = fields
            .next()
            .ok_or_else(|| git_error("missing path in git diff output"))?;
        let path = if matches!(status, b'R' | b'C') {
            fields
                .next()
                .ok_or_else(|| git_error("missing destination path in git diff output"))?
        } else {
            first_path
        };

        if new_mode == "160000" {
            continue;
        }
        blobs.push(GitBlob {
            path: PathBuf::from(String::from_utf8_lossy(path).into_owned()),
            object_id: object_id.to_string(),
            content: Vec::new(),
        });
    }

    Ok(blobs)
}

pub(crate) fn list_tracked_blobs(repo_root: &Path) -> Result<Vec<GitBlob>> {
    let output = run_git(
        repo_root,
        &["ls-files", "--stage", "-z"],
        "git ls-files --stage",
    )?;

    let mut blobs = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            return Err(git_error("unexpected git ls-files output"));
        };
        let metadata = std::str::from_utf8(&entry[..tab])
            .map_err(|_| git_error("invalid git ls-files metadata"))?;
        let parts: Vec<&str> = metadata.split_ascii_whitespace().collect();
        if parts.len() != 3 {
            return Err(git_error(format!(
                "unexpected git ls-files metadata: {metadata}"
            )));
        }
        if parts[2] != "0" {
            return Err(git_error("cannot scan an index with unmerged files"));
        }
        if parts[0] == "160000" {
            continue;
        }
        blobs.push(GitBlob {
            path: PathBuf::from(String::from_utf8_lossy(&entry[tab + 1..]).into_owned()),
            object_id: parts[1].to_string(),
            content: Vec::new(),
        });
    }

    Ok(blobs)
}

fn run_git(repo_root: &Path, args: &[&str], operation: &str) -> Result<Output> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .map_err(|source| Error::io(format!("failed to execute {operation}"), source))?;
    if !output.status.success() {
        return Err(git_error(format!(
            "{operation} failed with status {}",
            output.status
        )));
    }
    Ok(output)
}

type CatFile = (
    Child,
    BufReader<ChildStdout>,
    JoinHandle<std::io::Result<()>>,
);

/// Starts `git cat-file <mode>` and feeds it the object ids from a separate thread.
fn spawn_cat_file(repo_root: &Path, mode: &str, object_ids: Vec<String>) -> Result<CatFile> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["cat-file", mode])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|source| Error::io("failed to read staged git objects", source))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| git_error("failed to open git cat-file stdin"))?;
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        for object_id in object_ids {
            writeln!(stdin, "{object_id}")?;
        }
        Ok(())
    });
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| git_error("failed to open git cat-file stdout"))?;
    Ok((child, BufReader::new(stdout), writer))
}

fn finish_cat_file(mut child: Child, writer: JoinHandle<std::io::Result<()>>) -> Result<()> {
    let status = child.wait().map_err(read_error)?;
    writer
        .join()
        .map_err(|_| git_error("git cat-file input thread panicked"))?
        .map_err(|source| Error::io("failed to write to git cat-file", source))?;
    if !status.success() {
        return Err(git_error(format!(
            "git cat-file failed with status {status}"
        )));
    }
    Ok(())
}

/// Reads one `<id> blob <size>` header line and returns the size.
fn read_blob_header(reader: &mut impl BufRead, blob: &GitBlob) -> Result<usize> {
    let mut header = String::new();
    reader.read_line(&mut header).map_err(read_error)?;
    let mut parts = header.split_ascii_whitespace();
    let returned_id = parts.next().ok_or_else(|| {
        git_error(format!(
            "missing object id for staged object {}",
            blob.object_id
        ))
    })?;
    let object_type = parts
        .next()
        .ok_or_else(|| git_error(format!("missing type for staged object {}", blob.object_id)))?;
    let size = parts
        .next()
        .ok_or_else(|| git_error(format!("missing size for staged object {}", blob.object_id)))?
        .parse::<usize>()
        .map_err(|_| git_error(format!("invalid size for staged object {}", blob.object_id)))?;
    if returned_id != blob.object_id || object_type != "blob" {
        return Err(git_error(format!(
            "unexpected staged object response: {}",
            header.trim()
        )));
    }
    Ok(size)
}

/// Loads the blob contents. Blobs larger than `max_size` are dropped from the result
/// without their content being read.
pub(crate) fn load_git_blob_contents(
    repo_root: &Path,
    mut blobs: Vec<GitBlob>,
    max_size: Option<u64>,
) -> Result<Vec<GitBlob>> {
    let object_ids = |blobs: &[GitBlob]| blobs.iter().map(|blob| blob.object_id.clone()).collect();

    if let (Some(max), false) = (max_size, blobs.is_empty()) {
        let (child, mut reader, writer) =
            spawn_cat_file(repo_root, "--batch-check", object_ids(&blobs))?;
        let mut within_limit = Vec::with_capacity(blobs.len());
        for blob in blobs {
            if read_blob_header(&mut reader, &blob)? as u64 <= max {
                within_limit.push(blob);
            }
        }
        finish_cat_file(child, writer)?;
        blobs = within_limit;
    }
    if blobs.is_empty() {
        return Ok(blobs);
    }

    let (child, mut reader, writer) = spawn_cat_file(repo_root, "--batch", object_ids(&blobs))?;
    for blob in &mut blobs {
        let size = read_blob_header(&mut reader, blob)?;
        blob.content.resize(size, 0);
        reader.read_exact(&mut blob.content).map_err(read_error)?;
        let mut newline = [0_u8; 1];
        reader.read_exact(&mut newline).map_err(read_error)?;
        if newline[0] != b'\n' {
            return Err(git_error("invalid staged object delimiter"));
        }
    }
    finish_cat_file(child, writer)?;
    Ok(blobs)
}
