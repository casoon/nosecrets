# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Breaking

- **CLI:** a scan that cannot run exits with status 2 instead of 1; status 1 now always means blocking findings. A path that does not exist is such an error instead of a clean result.
- **Configuration:** unknown keys in `.nosecrets.toml` and in rule files are errors, as are rules with an empty `id` or `pattern` or with `min_length` above `max_length`.
- **Inline ignores:** `@nsi` and `@nosecrets-ignore` count only as separate words; the same characters inside an e-mail address or another word no longer suppress the findings of that line.

### Added

- **Configuration:** `[scan] max_file_size` skips files above a size limit (default 5 MiB) and reports how many were skipped. Details: [Configuration](https://casoon.github.io/nosecrets/docs/getting-started/configuration/).
- **Inline ignores:** `gitleaks:allow` is accepted as a marker.
- **pre-commit:** hook `nosecrets-system` runs the installed binary.
- **Rules:** optional field `generic` marks catch-all rules.

### Changed

- **Output:** when several rules match the same text, only the most severe one is reported, and a specific rule wins over a generic one; findings are sorted by path, line and column.
- **Output:** the preview reveals at most a quarter of a secret and nothing of secrets shorter than 12 characters. Fingerprints are unchanged.
- **Scanning:** ignored directories are no longer read; path scans skip them without descending.
- **Site:** the start page now carries a release teaser and an FAQ (theme 0.11.1).
- **Build:** building from source requires Rust 1.88 (was 1.85), as `sha2` 0.11 needs it.

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
