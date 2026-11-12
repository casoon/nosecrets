# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Rules:** AI provider keys (Anthropic, OpenAI, Hugging Face, Groq, xAI, OpenRouter, Replicate, Perplexity) and developer-tool tokens (1Password, Doppler, Docker Hub, Sentry, Linear, Notion, Postman, Databricks, Shopify, Telegram bot); 75 built-in rules in total.
- **Rules:** the changed token formats of GitHub App installation tokens, Cloudflare (`cfk_`, `cfut_`, `cfat_`, `cfoat_`), Vercel, Supabase (`sb_secret_`, `sbp_`), GitLab (routable) and Slack (`xapp-`, `xoxe`) are detected. Where the vendor documents only the prefix, the rest of the token is matched loosely.
- **Rules:** `validate.checksum = "crc32-base62-suffix6"` for custom rules. Details: [Custom rules](https://casoon.github.io/nosecrets/docs/reference/custom-rules/).
- **Site:** the [Showcase](https://casoon.github.io/nosecrets/showcase/) shows eight use cases as real nosecrets runs next to the files they scan, and the start page links the most common ones.
- **README:** a recorded terminal scene and the same real examples.
- **Entropy:** `[entropy] word_filter` (default `true`) skips candidates in which common English and programming words cover at least half of the characters, such as `getUserAuthenticationTokenFromRequest`. Details: [Configuration](https://casoon.github.io/nosecrets/docs/getting-started/configuration/).
- **Docs:** [Performance](https://casoon.github.io/nosecrets/docs/reference/performance/) lists measured timings for a commit, a tracked scan and a working-tree scan, with the machine they were taken on.
- **Detection:** secrets stored base64-encoded (Kubernetes `Secret` values, `.env` values, CI variables) are found. Tokens of 24 or more base64 characters are decoded one level deep (standard and URL-safe alphabet) and matched against the rules; the finding sits at the encoded token and is marked `(base64)` in text and `"encoding": "base64"` in JSON. Disable with `[decode] base64 = false`. Details: [Configuration](https://casoon.github.io/nosecrets/docs/getting-started/configuration/).
- **Contributors:** `scripts/bench.sh` builds the release binary, generates a deterministic repository and measures the scans with hyperfine.

### Changed

- **Entropy:** `${VAR}`, `${VAR:-default}` and `${obj.prop}` interpolation, access such as `os.environ["X"]` and generic type signatures such as `Promise<Foo<boolean>>` are no longer reported; a literal token next to them still is.
- **Pages:** the project site uses the current shared theme (0.12.12).
- **Pages:** the project site uses the shared theme 0.12.10.

## [0.4.0] - 2026-11-11

### Breaking

- **CLI:** a scan that cannot run exits with status 2 instead of 1; status 1 now always means blocking findings. A path that does not exist is such an error instead of a clean result.
- **Configuration:** unknown keys in `.nosecrets.toml` and in rule files are errors, as are rules with an empty `id` or `pattern` or with `min_length` above `max_length`.
- **Inline ignores:** `@nsi` and `@nosecrets-ignore` count only as separate words; the same characters inside an e-mail address or another word no longer suppress the findings of that line.
- **Library:** the crates `nosecrets-rules`, `nosecrets-filter` and `nosecrets-report` are merged into `nosecrets-core`, which exports their types directly and returns one error type, `nosecrets_core::Error`. The three crates are no longer developed; the deprecated `collect_staged_files` is removed.

### Added

- **Configuration:** `[scan] max_file_size` skips files above a size limit (default 5 MiB) and reports how many were skipped. Details: [Configuration](https://casoon.github.io/nosecrets/docs/getting-started/configuration/).
- **Inline ignores:** `gitleaks:allow` is accepted as a marker.
- **pre-commit:** hook `nosecrets-system` runs the installed binary.
- **Rules:** optional field `generic` marks catch-all rules.

### Changed

- **Output:** when several rules match the same text, only the most severe one is reported, and a specific rule wins over a generic one; findings are sorted by path, line and column.
- **Output:** the preview reveals at most a quarter of a secret and nothing of secrets shorter than 12 characters. Fingerprints are unchanged.
- **Scanning:** ignored directories are no longer read; path scans skip them without descending.
- **Pages:** the project site uses the current shared theme (0.12.8).
- **Site:** the start page now carries a release teaser and an FAQ (theme 0.11.1).
- **Build:** building from source requires Rust 1.88 (was 1.85), as `sha2` 0.11 needs it.
- **Crates:** `nosecrets-core` and `nosecrets-cli` are published from the release workflow via Trusted Publishing, after approval in the `crates-io` environment; no local `cargo publish`.
- **Dependencies:** `toml` 1.x; `console` and `hex` are no longer used.
- **Docs:** concept, architecture and rule format are documented in one place, the [project documentation](https://casoon.github.io/nosecrets/docs/concepts/how-it-works/); `CONCEPT.md`, `ARCHITECTURE.md` and `RULES_SPEC.md` are removed. The JSON output is specified in the [CLI reference](https://casoon.github.io/nosecrets/docs/reference/cli/#json-output).
- **Contributors:** CI checks advisories and licences with `cargo-deny`, actions are pinned to commit SHAs, and Dependabot proposes weekly updates.

### Fixed

- **pre-commit:** the hook `nosecrets`, which builds the binary from source, installs again.

### Security

- **Site:** the project site builds with Astro 7.4.4 and updated dependencies, which closes the advisories for `devalue`, `vite`, `undici`, `zod`, `source-map-js`, `fast-uri` and Astro itself.
- **Crates:** `nosecrets-report` uses `sha2` 0.11, so `block-buffer` 0.10.4 (GHSA-qwgh-2vcv-g2f7) is no longer pulled in; fingerprints stay identical, existing `.nosecretsignore` entries keep working.

## [0.3.9] - 2026-10-26

### Added

- **Releases:** the binaries carry a signed build provenance attestation (verify with `gh attestation verify`).

### Changed

- **npm:** `@casoon/nosecrets` is published from the release workflow via Trusted Publishing (provenance, no stored token), after approval in the `npm` environment.
- **Contributors:** CI runs `nosecrets scan --tracked` on the repository itself; test fixtures,
  rule definitions and the synthetic entropy test token are excepted in `.nosecrets.toml`.

## [0.3.8] - 2026-09-14

### Added

- `scan --tracked` for a one-time baseline of all tracked Git-index blobs.
- Repeatable `--rules <FILE>` support for repository-specific TOML rules.
- Behavioral fixtures covering all 50 built-in rules.
- GitHub Pages documentation.

### Fixed

- `scan --staged` now reads the exact staged blobs instead of working-tree copies.
- Scan read errors now fail the command rather than being silently ignored.
- Release publishing and downloaded archive checksum verification are strict.

### Changed

- Removed unused dependencies and the vulnerable transitive `gix` dependency tree.
- Intel macOS installation now directs users to the supported Cargo build.
