# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
