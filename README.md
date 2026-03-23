# nosecrets

[![Crates.io](https://img.shields.io/crates/v/nosecrets-cli.svg)](https://crates.io/crates/nosecrets-cli)
[![CI](https://github.com/casoon/nosecrets/actions/workflows/ci.yml/badge.svg)](https://github.com/casoon/nosecrets/actions/workflows/ci.yml)

Fast, offline secret scanner for Git pre-commit. Designed to be simple, fast, and safe for any GitHub repository.

## Highlights

- Pre-commit focus (no history scanning)
- Offline only, no API calls
- Fast scanning (regex + validation + prefilter)
- High-entropy detection for unknown secrets
- Minimal configuration

## Install

### npm (recommended)

```
npm install -g @casoon/nosecrets
```

The npm package ships the prebuilt CLI binaries for supported macOS, Linux, and Windows targets and selects the right one at runtime.

### Homebrew (macOS)

Coming soon once nosecrets has been battle-tested.

### Cargo (Rust)

```
cargo install nosecrets-cli
```

### From source

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

### High-entropy detection

nosecrets includes an entropy-based detection layer that catches unknown or proprietary secrets that don't match any known regex rule. It is enabled by default and can be configured:

```toml
[entropy]
enabled = true
min_length = 20
threshold = 4.2
require_context = true

[entropy.allow]
patterns = [
  "^[a-f0-9]{32,}$",
  "^[A-F0-9]{32,}$",
]
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable or disable entropy detection |
| `min_length` | `20` | Minimum token length to consider |
| `threshold` | `4.2` | Shannon entropy threshold (bits per char) |
| `require_context` | `true` | Only flag tokens near secret-related variable names (`secret`, `token`, `key`, `auth`, `password`, etc.) |

When `require_context` is `true` (default), only tokens found near variable names like `SECRET_KEY`, `AUTH_TOKEN`, `password`, etc. are flagged. This dramatically reduces false positives.

Entropy findings use rule ID `high-entropy-string` with severity `medium` and work with all existing filtering mechanisms (`.nosecretsignore`, inline ignores, allowlists, fingerprints).

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
- `rules/code.toml` (GitHub/GitLab/npm/Slack/Discord, etc.)
- `rules/communication.toml` (SendGrid, Twilio, Mailchimp, Mailgun)
- `rules/database.toml` (Postgres/MySQL/Mongo/Redis, JDBC passwords)
- `rules/payment.toml` (Stripe)
- `rules/generic.toml` (private keys, generic secrets, passwords)
- High-entropy detection (unknown tokens, proprietary secrets)

### Help improve the rules

The built-in rules are a starting point, but this tool becomes more valuable as the rule set grows and improves. You can define your own rules in a local TOML file, but if you discover new secret patterns or improve existing ones, please consider contributing them back.

**Contributions welcome:**
- New rules for services not yet covered
- Improvements to existing patterns (better regex, fewer false positives)
- Bug reports for missed secrets or false positives

Open an issue or pull request at [github.com/casoon/nosecrets](https://github.com/casoon/nosecrets).

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

## Release

Create and push a version tag from this repository:

```bash
git tag v0.3.1
git push origin v0.3.1
```

The tag workflow waits for CI, builds release binaries, publishes the GitHub release assets, and publishes all crates to crates.io.

The npm package is published manually from `packages/npm` after the release assets exist:

```bash
cd packages/npm
npm publish
```

`prepack` automatically downloads the matching GitHub release assets for the current package version and populates `vendor/` before publishing.

## License

MIT
