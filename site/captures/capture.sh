#!/usr/bin/env bash
# Regenerates the terminal captures on the start page: real nosecrets runs against the
# fixture in fixture/. Each run stages fixture/<state>/config.py in a throwaway Git
# repository and runs `nosecrets scan --staged`, exactly as the pre-commit hook does.
#   site/captures/capture.sh   (after cargo build --release)
# The keys in the fixture are the example keys from the AWS documentation. The key ID ends
# in EXAMPLE and is skipped by the aws-access-key rule; the secret key is reported.
# The repository's own .nosecrets.toml ignores fixture/ so scans of nosecrets itself pass.
# Rebuild the scene after a capture:
#   cd site/captures && npx -y -p @casoon/castwright@0.5.0 -p shiki castwright build scan.terminal.yaml --format svg -o .
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
out="$repo/site/captures"
bin="$repo/target/release/nosecrets"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git -C "$work" init -q

for state in leaky fixed; do
  cp "$out/fixture/$state/config.py" "$work/config.py"
  git -C "$work" add config.py
  status=0
  (cd "$work" && "$bin" scan --staged) > "$out/scan-$state.txt" || status=$?
  echo "$status" > "$out/exit-$state.txt"
done
