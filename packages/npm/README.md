# @casoon/nosecrets

Fast, offline secret scanner for Git pre-commit hooks.

## Install

```bash
npm install -g @casoon/nosecrets
```

## Usage

```bash
# Scan staged files (pre-commit)
nosecrets scan --staged

# Scan a directory
nosecrets scan src/

# Interactive mode
nosecrets scan --staged --interactive
```

## Features

- 100+ built-in rules for AWS, GitHub, Stripe, database URLs, and more
- High-entropy detection for unknown or proprietary secrets
- Offline only — no API calls, no data leaves your machine
- Configurable via `.nosecrets.toml`

The package ships prebuilt binaries for macOS (x64/arm64), Linux (x64/arm64), and Windows (x64).

## Publishing

Publish manually from this directory:

```bash
npm publish
```

Before packing, `prepack` runs `npm run prepare-release`, which downloads the release assets for the current package version from GitHub and populates `vendor/` automatically.

Full documentation: <https://github.com/casoon/nosecrets>
