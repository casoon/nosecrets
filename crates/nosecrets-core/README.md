# nosecrets-core

[![Crates.io](https://img.shields.io/crates/v/nosecrets-core.svg)](https://crates.io/crates/nosecrets-core)

Scanning engine of [nosecrets](https://crates.io/crates/nosecrets-cli): rule parsing and the
built-in rules, ignore and allow filters, detection (regex rules and entropy) and reporting.
The crates `nosecrets-rules`, `nosecrets-filter` and `nosecrets-report` were merged into this
one in 0.4.0.

```rust
use nosecrets_core::{load_builtin_rules, Detector, Error, Filter};

fn main() -> Result<(), Error> {
    let filter = Filter::from_config(None, Vec::new())?;
    let detector = Detector::new(load_builtin_rules()?, filter)?;
    let root = std::path::Path::new(".");
    let files = detector.collect_files(root, &[])?;
    for finding in detector.scan_files(root, &files)? {
        println!("{}:{} {}", finding.path, finding.line, finding.rule_id);
    }
    Ok(())
}
```

To scan a repository, install the CLI instead:

```bash
cargo install nosecrets-cli
```

## License

MIT
