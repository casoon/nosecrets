# nosecrets (v0.1.0)

Fast, offline secret scanner for Git pre-commit. Designed to be simple, fast, and safe for any GitHub repository.

## Highlights

- Pre-commit focus (no history scanning)
- Offline only, no API calls
- Fast scanning (regex + validation + prefilter)
- Minimal configuration

## Install

### npm (recommended)

```
npm install -g @casoon/nosecrets
```

### Homebrew (macOS)

Coming soon once nosecrets has been battle-tested.

### From source (Rust)

```
cargo install --path crates/nosecrets-cli
```

## Usage

```
# Scan staged files
nosecrets scan --staged

# Scan a directory
nosecrets scan src/

# Interactive mode (add ignores)
nosecrets scan --staged --interactive

# Add ignore by fingerprint
nosecrets ignore nsi_abcdef123456
```

### Exit codes

- 0: no blocking findings (only low or none)
- 1: blocking findings (critical/high/medium)

## Configuration

### .nosecrets.toml

```
[ignore]
paths = [
  "vendor/",
  "node_modules/",
  "*.lock",
]

[allow]
patterns = [
  "EXAMPLE",
  "changeme",
  "YOUR_.*_HERE",
]

values = [
  "AKIAIOSFODNN7EXAMPLE",
]
```

### .nosecretsignore

```
# Format: nsi_<hash> or nsi_<hash>:<path-glob>
nsi_a1b2c3d4e5f6
nsi_b2c3d4e5f6a7:src/config.py
```

### Inline ignore

```
api_key = "sk_test_xxx"  # @nosecrets-ignore
api_key = "sk_test_xxx"  # @nsi example key
```

## Default rules

Rules are shipped in TOML files under `rules/`:

- `rules/cloud.toml` (AWS/GCP/Azure/Cloudflare, etc.)
- `rules/deploy.toml` (Netlify, Fly.io, Heroku, Vercel, Railway, Render, Supabase)
- `rules/code.toml` (GitHub/GitLab/npm, etc.)
- `rules/database.toml` (Postgres/MySQL/Mongo/Redis, JDBC passwords)
- `rules/generic.toml` (private keys, generic secrets, passwords)

## Pre-commit integration

Example `.pre-commit-hooks.yaml` entry:

```
- repo: local
  hooks:
    - id: nosecrets
      name: nosecrets
      entry: nosecrets scan --staged
      language: system
      pass_filenames: false
```

## Development

```
cargo test
cargo run -p nosecrets-cli -- scan --staged
```

## License

MIT
