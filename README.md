# nosecrets

[![Crates.io](https://img.shields.io/crates/v/nosecrets-cli.svg)](https://crates.io/crates/nosecrets-cli)
[![CI](https://github.com/casoon/nosecrets/actions/workflows/ci.yml/badge.svg)](https://github.com/casoon/nosecrets/actions/workflows/ci.yml)

Fast, offline secret scanner for Git pre-commit. It checks what a commit is about to contain and stops the commit when it finds a password, token or key, on your own machine, without an account or a network call.

<p align="center">
  <img src="site/captures/scan.svg" width="561" alt="Terminal: after git add config.py, nosecrets scan --staged reports an AWS secret access key in config.py and exits with 1; with the key read from the environment the same scan prints 'No secrets found' and exits with 0.">
</p>

**Documentation:** [casoon.github.io/nosecrets](https://casoon.github.io/nosecrets/) · **Examples:** [Showcase](https://casoon.github.io/nosecrets/showcase/)

## Highlights

- Checks exactly what the next commit contains (the Git index), not the working tree
- Offline only: no API calls, no verification against providers, no history scanning
- 75 built-in rules plus your own; an entropy check for tokens no rule knows
- Exceptions live in files in the repository, so they show up in code review
- Exit status 0, 1 or 2, JSON output for scripts and SARIF for GitHub code scanning (`--format sarif`)
- Prefilter, regex and a format check (prefix, charset, length) keep it quiet; a commit with 10 changed files takes about 65 ms on an Apple M4 Pro ([Performance](https://casoon.github.io/nosecrets/docs/reference/performance/))

## In practice

Every example below is a real run of the released binary against made-up tokens; the [Showcase](https://casoon.github.io/nosecrets/showcase/) has the files next to each session.

### Stop a leak before it is committed

```text
$ git add deploy.py .env
$ nosecrets scan --staged
.env:2:31 [HIGH] Postgres Connection URI (postgres-connection-uri) nsi_31013ade6422
  preview: Tr0...
deploy.py:3:17 [CRITICAL] GitHub Personal Access Token (github-pat) nsi_5e31772c2cb9
  preview: ghp_...PeXq
$ echo $?
1
```

The commit stops (exit status 1). The report names file, line, rule and a masked preview, never the secret itself. Deleting the line afterwards does not help: the [staged blob is what counts](https://casoon.github.io/nosecrets/showcase/staged-snapshot/).

### Adopt it in a repository that already exists

```text
$ nosecrets scan --tracked
legacy/import_users.py:2:17 [CRITICAL] GitHub Personal Access Token (github-pat) nsi_5e31772c2cb9
  preview: ghp_...PeXq
$ nosecrets ignore nsi_5e31772c2cb9 --path legacy/import_users.py
Added ignore entry to .nosecretsignore
$ cat .nosecretsignore
nsi_5e31772c2cb9:legacy/import_users.py
$ nosecrets scan --tracked
No secrets found
```

`scan --tracked` checks every tracked file once. A known old value is accepted by fingerprint and path; the entry is a line in `.nosecretsignore`.

### Your own token formats

```toml
[[rule]]
id = "acme-service-token"
name = "Acme service token"
severity = "high"
pattern = '''\b(acme_[A-Za-z0-9]{24})\b'''
keywords = ["acme_"]
capture = 1
```

```text
$ git add deploy.sh
$ nosecrets scan --staged --rules team-rules.toml
deploy.sh:2:24 [HIGH] Acme service token (acme-service-token) nsi_a7570523585c
  preview: acme...
```

### More

- [Exceptions on purpose](https://casoon.github.io/nosecrets/showcase/exceptions/): inline `@nsi` marker, ignored paths, allowed values.
- [A token no rule knows](https://casoon.github.io/nosecrets/showcase/entropy/): the entropy check.
- [Machine-readable output](https://casoon.github.io/nosecrets/showcase/json/): `--format json`.
- [A typo in the configuration](https://casoon.github.io/nosecrets/showcase/bad-config/): an error with exit status 2, never a silent pass.

## Install

### curl (Apple Silicon macOS and Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/casoon/nosecrets/main/install.sh | sh
```

Installs the prebuilt binary to `/usr/local/bin`. Override the target directory:

```sh
NOSECRETS_INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/casoon/nosecrets/main/install.sh | sh
```

### npm

```
npm install -g @casoon/nosecrets
```

Official binaries come only from the GitHub releases of `casoon/nosecrets` — built there by the
release workflow, never on a developer machine. The npm package is published from the same
workflow with provenance. To verify a downloaded archive by hand, check the hash and the signed
build provenance:

```sh
grep " nosecrets-aarch64-apple-darwin.tar.gz" SHA256SUMS | shasum -a 256 -c
gh attestation verify nosecrets-aarch64-apple-darwin.tar.gz --repo casoon/nosecrets
```

### Cargo (Rust)

```
cargo install nosecrets-cli
```

## Usage

```
# Scan staged files
nosecrets scan --staged

# Initial scan of every Git-tracked file
nosecrets scan --tracked

# Scan a directory
nosecrets scan src/

# Load additional rules
nosecrets scan --rules .nosecrets-rules.toml src/

# Interactive mode (add ignores)
nosecrets scan --staged --interactive

# Add ignore by fingerprint
nosecrets ignore nsi_abcdef123456
```

For an existing repository, run `nosecrets scan --tracked` once when adopting the tool. It scans the complete Git index without including untracked files or unrelated working-tree changes. The pre-commit command `nosecrets scan --staged` then scans only the files changed for the next commit, using their exact staged contents.

### Exit codes

- 0: no blocking findings (only low or none)
- 1: blocking findings (critical/high/medium)
- 2: the scan could not run, for example an invalid configuration, a path that does not exist or `--staged` outside a Git repository

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

[scan]
max_file_size = 5242880
```

Files larger than `max_file_size` bytes (default 5 MiB) are skipped and counted in a note on stderr; `0` removes the limit. Unknown keys in `.nosecrets.toml` are an error, so a misspelled option cannot go unnoticed.

### High-entropy detection

nosecrets includes an entropy-based detection layer that catches unknown or proprietary secrets that don't match any known regex rule. It is enabled by default and can be configured:

```toml
[entropy]
enabled = true
min_length = 20
threshold = 4.2
require_context = true
word_filter = true

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
| `word_filter` | `true` | Skip candidates in which common English and programming words cover at least half of the characters (`getUserAuthenticationTokenFromRequest`, `MAX_CONNECTION_RETRY_TIMEOUT`) |

When `require_context` is `true` (default), only tokens found near variable names like `SECRET_KEY`, `AUTH_TOKEN`, `password`, etc. are flagged. This dramatically reduces false positives.

The entropy layer also skips values that are variable references or type signatures, not literals: `${VAR}`, `${VAR:-default}` and `${obj.prop}` interpolation, access such as `os.environ["X"]` and generic types such as `Promise<Foo<boolean>>`. A literal token next to such a construct is still reported.

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
api_key = "sk_test_xxx"  # gitleaks:allow
```

A marker counts only as a separate word in a comment; `@nsi` inside an e-mail address or another word does not suppress anything.

## Default rules

Rules are shipped in TOML files under `crates/nosecrets-core/rules/`:

- `rules/ai.toml` (Anthropic, OpenAI, Hugging Face, Groq, xAI, OpenRouter, Replicate, Perplexity)
- `rules/cloud.toml` (AWS/GCP/Azure/Cloudflare, Databricks, etc.)
- `rules/deploy.toml` (Netlify, Fly.io, Heroku, Vercel, Railway, Render, Supabase, Doppler)
- `rules/code.toml` (GitHub/GitLab/npm/Slack/Discord, Docker Hub, Sentry, Linear, Notion, Postman, 1Password, etc.)
- `rules/communication.toml` (SendGrid, Twilio, Mailchimp, Mailgun, Telegram)
- `rules/database.toml` (Postgres/MySQL/Mongo/Redis, JDBC passwords)
- `rules/payment.toml` (Stripe, Square, PayPal, Shopify)
- `rules/generic.toml` (private keys, generic secrets, passwords)
- High-entropy detection (unknown tokens, proprietary secrets)

### Help improve the rules

The built-in rules are a starting point, but this tool becomes more valuable as the rule set grows and improves. Load additional local TOML rules with `--rules <FILE>`; the format is documented under [Custom rules](https://casoon.github.io/nosecrets/docs/reference/custom-rules/). The option may be repeated. If you discover new secret patterns or improve existing ones, please consider contributing them back.

**Contributions welcome:**
- New rules for services not yet covered
- Improvements to existing patterns (better regex, fewer false positives)
- Bug reports for missed secrets or false positives

Open an issue or pull request at [github.com/casoon/nosecrets](https://github.com/casoon/nosecrets). See the [GitHub Pages documentation](https://casoon.github.io/nosecrets/) for the complete guide.

## False positives

nosecrets can produce false positives — especially the entropy-based detection. If you encounter one, please [open an issue](https://github.com/casoon/nosecrets/issues) with an example of the flagged line so we can improve the detection. You can always suppress individual findings with inline ignores or fingerprints in the meantime.

## Pre-commit integration

With [pre-commit](https://pre-commit.com/) or [prek](https://github.com/j178/prek), using the
installed `nosecrets` binary:

```yaml
repos:
  - repo: https://github.com/casoon/nosecrets
    rev: v0.4.0 # a release tag
    hooks:
      - id: nosecrets-system
```

Use `id: nosecrets` instead to have the hook build the binary from source; that needs a Rust
toolchain but no installed `nosecrets`.

With [lefthook](https://lefthook.dev/) (`lefthook.yml`):

```yaml
pre-commit:
  commands:
    nosecrets:
      run: nosecrets scan --staged
```

With [husky](https://typicode.github.io/husky/) (`.husky/pre-commit`) or as a plain
`.git/hooks/pre-commit` script:

```sh
#!/bin/sh
nosecrets scan --staged
```

## Development

```
cargo test
cargo run -p nosecrets-cli -- scan --staged
```

## Release

1. Set the new version in `Cargo.toml` (`[workspace.package]` and the `nosecrets-core` dependency) and in `packages/npm/package.json`.
2. Move the entries under `## [Unreleased]` in `CHANGELOG.md` to the new version.
3. Commit, then tag and push:

```bash
git tag vX.Y.Z
git push origin main vX.Y.Z
```

The tag workflow waits for CI, checks that the tag matches both manifests, and then publishes everything from GitHub Actions: `nosecrets-core` and `nosecrets-cli` to crates.io and `@casoon/nosecrets` to npm (both via Trusted Publishing, after approval in the `crates-io` and `npm` environments), and the binaries with `SHA256SUMS` and build provenance to the GitHub release. Nothing is published from a developer machine.

## License

MIT
