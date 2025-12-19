use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use nosecrets_core::{collect_files, collect_staged_files, discover_repo_root, Detector};
use nosecrets_filter::{load_ignore_file, normalize_path, Config, Filter};
use nosecrets_report::Report;
use nosecrets_rules::load_builtin_rules;

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
    #[arg(long)]
    staged: bool,
    /// Ask to ignore findings interactively
    #[arg(long)]
    interactive: bool,
    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan(args) => run_scan(args),
        Commands::Ignore(args) => run_ignore(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("failed to read current dir")?;
    let repo_root = discover_repo_root(&cwd)?;
    let root = repo_root.clone().unwrap_or(cwd);

    let config = Config::load_from_dir(&root)?;
    let ignore_entries = load_ignore_file(&root.join(".nosecretsignore"))?;
    let filter = Filter::from_config(config, ignore_entries)?;
    let rules = load_builtin_rules()?;
    let detector = Detector::new(rules, filter)?;

    let files = if args.staged {
        let Some(repo_root) = repo_root else {
            return Err(anyhow::anyhow!("--staged requires a git repository"));
        };
        collect_staged_files(&repo_root)?
    } else {
        collect_files(&root, &args.paths)?
    };

    let findings = detector.scan_files(&root, &files)?;
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
    std::process::exit(report.exit_code());
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

fn interactive_filter(root: &Path, findings: Vec<nosecrets_report::Finding>) -> Result<Vec<nosecrets_report::Finding>> {
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
