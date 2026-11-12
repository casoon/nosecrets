use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use nosecrets_core::{
    discover_repo_root, load_builtin_rules, load_ignore_file, normalize_path, parse_rules, Config,
    Detector, Filter, Finding, Report,
};

#[derive(Parser, Debug)]
#[command(name = "nosecrets", version, about = "Fast offline secret scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan files or staged changes
    Scan(ScanArgs),
    /// Add an ignore entry to .nosecretsignore
    Ignore(IgnoreArgs),
}

#[derive(Parser, Debug)]
struct ScanArgs {
    /// Scan staged files
    #[arg(long, conflicts_with_all = ["tracked", "paths"])]
    staged: bool,
    /// Scan all Git-tracked files from the index
    #[arg(long, conflicts_with_all = ["staged", "paths"])]
    tracked: bool,
    /// Ask to ignore findings interactively
    #[arg(long)]
    interactive: bool,
    /// Show findings but always exit with code 0
    #[arg(long)]
    dry_run: bool,
    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
    /// Load additional detection rules from a TOML file
    #[arg(long = "rules", value_name = "FILE")]
    rule_files: Vec<PathBuf>,
    /// Files or directories to scan
    paths: Vec<PathBuf>,
}

#[derive(Parser, Debug)]
struct IgnoreArgs {
    /// Fingerprint to ignore (nsi_...)
    fingerprint: String,
    /// Optional path glob to scope the ignore
    #[arg(long)]
    path: Option<PathBuf>,
    /// Override .nosecretsignore location
    #[arg(long)]
    file: Option<PathBuf>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum OutputFormat {
    Text,
    Json,
}

/// Exit code for a scan that could not be completed, as opposed to `1` for blocking findings.
const EXIT_ERROR: i32 = 2;

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Ignore(args) => run_ignore(args).map(|()| 0),
    };
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("Error: {error:#}");
            std::process::exit(EXIT_ERROR);
        }
    }
}

fn run_scan(args: ScanArgs) -> Result<i32> {
    let cwd = std::env::current_dir().context("failed to read current dir")?;
    let repo_root = discover_repo_root(&cwd)?;
    let root = repo_root.clone().unwrap_or(cwd);

    let config = Config::load_from_dir(&root)?;
    let entropy_config = config
        .as_ref()
        .map(|c| c.entropy.clone())
        .unwrap_or_default();
    let decode_config = config
        .as_ref()
        .map(|c| c.decode.clone())
        .unwrap_or_default();
    let ignore_entries = load_ignore_file(&root.join(".nosecretsignore"))?;
    let filter = Filter::from_config(config, ignore_entries)?;
    let mut rules = load_builtin_rules()?;
    for rule_file in &args.rule_files {
        let path = if rule_file.is_absolute() {
            rule_file.clone()
        } else {
            root.join(rule_file)
        };
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read rules from {}", path.display()))?;
        rules.extend(parse_rules(&content, &path.display().to_string())?);
    }
    let detector =
        Detector::with_entropy(rules, filter, entropy_config)?.with_decode(decode_config);

    let findings = if args.staged || args.tracked {
        let Some(repo_root) = repo_root else {
            return Err(anyhow::anyhow!(
                "--staged and --tracked require a git repository"
            ));
        };
        if args.staged {
            detector.scan_staged_files(&repo_root)?
        } else {
            detector.scan_tracked_files(&repo_root)?
        }
    } else {
        let files = detector.collect_files(&root, &args.paths)?;
        detector.scan_files(&root, &files)?
    };
    let findings = if args.interactive {
        interactive_filter(&root, findings)?
    } else {
        findings
    };

    let report = Report::new(findings);
    match args.format {
        OutputFormat::Text => report.print_terminal()?,
        OutputFormat::Json => report.print_json()?,
    }
    let skipped = detector.skipped_large_files();
    if skipped > 0 {
        eprintln!("skipped {skipped} file(s) larger than the configured scan.max_file_size");
    }
    Ok(if args.dry_run { 0 } else { report.exit_code() })
}

fn run_ignore(args: IgnoreArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read current dir")?;
    let root = discover_repo_root(&cwd)?.unwrap_or(cwd);
    let ignore_path = args.file.unwrap_or_else(|| root.join(".nosecretsignore"));
    let entry = if let Some(path) = args.path {
        format!("{}:{}", args.fingerprint, normalize_path(&path))
    } else {
        args.fingerprint
    };
    append_ignore(&ignore_path, &entry)?;
    println!("Added ignore entry to {}", ignore_path.display());
    Ok(())
}

fn interactive_filter(root: &Path, findings: Vec<Finding>) -> Result<Vec<Finding>> {
    if findings.is_empty() {
        return Ok(findings);
    }
    let ignore_path = root.join(".nosecretsignore");
    let mut remaining = Vec::new();
    for finding in findings {
        println!(
            "\n{}:{}:{} {} ({})",
            finding.path, finding.line, finding.column, finding.rule_name, finding.rule_id
        );
        println!("Fingerprint: {}", finding.fingerprint);
        print!("Ignore this finding? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let answer = input.trim().to_lowercase();
        if answer == "y" || answer == "yes" {
            let entry = format!("{}:{}", finding.fingerprint, finding.path);
            append_ignore(&ignore_path, &entry)?;
        } else {
            remaining.push(finding);
        }
    }
    Ok(remaining)
}

fn append_ignore(path: &Path, entry: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    writeln!(file, "{}", entry)?;
    Ok(())
}
