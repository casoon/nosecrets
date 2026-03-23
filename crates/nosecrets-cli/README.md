# nosecrets-cli

[![Crates.io](https://img.shields.io/crates/v/nosecrets-cli.svg)](https://crates.io/crates/nosecrets-cli)
[![CI](https://github.com/casoon/nosecrets/actions/workflows/ci.yml/badge.svg)](https://github.com/casoon/nosecrets/actions/workflows/ci.yml)

Fast, offline secret scanner for Git pre-commit hooks. Designed to be simple, fast, and safe for any repository.

## Highlights

- Pre-commit focus (no history scanning)
- Offline only, no API calls
- Fast scanning (regex + validation + prefilter)
- High-entropy detection for unknown secrets
- Minimal configuration

## Install

### Cargo (Rust)

```bash
cargo install nosecrets-cli
```

### npm

```bash
npm install -g @casoon/nosecrets
```

The npm package is published from the main `nosecrets` repository and bundles prebuilt binaries for supported platforms.

## Usage

```bash
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

- `0`: no blocking findings (only low or none)
- `1`: blocking findings (critical/high/medium)

## Configuration

### .nosecrets.toml

```toml
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

```python
api_key = "sk_test_xxx"  # @nosecrets-ignore
api_key = "sk_test_xxx"  # @nsi example key
```

## Built-in Rules

Detects secrets from:

- **Cloud**: AWS, GCP, Azure, DigitalOcean, Cloudflare
- **Code**: GitHub, GitLab, npm, Slack, Discord
- **Deploy**: Netlify, Fly.io, Heroku, Vercel, Railway, Render, Supabase
- **Communication**: SendGrid, Twilio, Mailchimp, Mailgun
- **Database**: PostgreSQL, MySQL, MongoDB, Redis
- **Payment**: Stripe
- **Generic**: Private keys, API keys, passwords
- **High-entropy**: Unknown tokens, proprietary secrets (Shannon entropy analysis)

### High-entropy Detection

nosecrets detects unknown secrets through entropy analysis. Enabled by default, configurable via `.nosecrets.toml`:

```toml
[entropy]
enabled = true
min_length = 20
threshold = 4.2
require_context = true
```

## Pre-commit Integration

```yaml
- repo: local
  hooks:
    - id: nosecrets
      name: nosecrets
      entry: nosecrets scan --staged
      language: system
      pass_filenames: false
```

## Related Crates

- [`nosecrets-core`](https://crates.io/crates/nosecrets-core) - Core scanning engine
- [`nosecrets-rules`](https://crates.io/crates/nosecrets-rules) - Rule definitions
- [`nosecrets-filter`](https://crates.io/crates/nosecrets-filter) - Filtering logic
- [`nosecrets-report`](https://crates.io/crates/nosecrets-report) - Output formatting

## License

MIT
