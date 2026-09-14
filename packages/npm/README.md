# @casoon/nosecrets

Fast, offline secret scanner for Git pre-commit hooks.

## Install

```bash
npm install -g @casoon/nosecrets
```

## Usage

```bash
# Initial scan of every tracked Git-index blob
nosecrets scan --tracked

# Scan staged files (pre-commit)
nosecrets scan --staged

# Scan a directory
nosecrets scan src/

# Interactive mode
nosecrets scan --staged --interactive
```

## Features

- 50 built-in rules for AWS, GitHub, Stripe, database URLs, and more
- High-entropy detection for unknown or proprietary secrets
- Offline only — no API calls, no data leaves your machine
- Configurable via `.nosecrets.toml`

The package ships prebuilt binaries for Apple Silicon macOS, Linux (x64/arm64), and Windows (x64).
Intel macOS users can install from crates.io with `cargo install nosecrets-cli`.

Full documentation: <https://casoon.github.io/nosecrets/>
