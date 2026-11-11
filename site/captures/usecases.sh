#!/usr/bin/env bash
# Regenerates the use case examples of the showcase: real nosecrets runs against the
# fixtures in usecases/<slug>/. For each use case the files in files/ become a throwaway Git
# repository, optional hidden setup commands run (setup), then every line of cmds is run
# and recorded like a terminal session.
#   site/captures/usecases.sh   (after cargo build --release)
# Writes usecases/<slug>/input.txt (the files) and transcript.ansi (commands and output).
# All tokens in the fixtures are made up and match no real account.
set -uo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
out="$repo/site/captures/usecases"
bin="$repo/target/release/nosecrets"
[ -x "$bin" ] || bin="$(cargo metadata --format-version 1 --no-deps --manifest-path "$repo/Cargo.toml" | jq -r .target_directory)/release/nosecrets"
shim="$(mktemp -d)"
ln -s "$bin" "$shim/nosecrets"
trap 'rm -rf "$shim"' EXIT

for dir in "$out"/*/; do
  slug="$(basename "$dir")"
  work="$(mktemp -d)"
  cp -R "$dir/files/." "$work/"
  (cd "$work" && git init -q)

  # input.txt: every fixture file under a "# <path>" heading.
  : > "$dir/input.txt"
  (cd "$dir/files" && find . -type f | sed 's|^\./||' | sort) | while read -r file; do
    printf '# %s\n' "$file" >> "$dir/input.txt"
    cat "$dir/files/$file" >> "$dir/input.txt"
    printf '\n' >> "$dir/input.txt"
  done

  if [ -f "$dir/setup" ]; then
    (cd "$work" && PATH="$shim:$PATH" bash "$dir/setup" > /dev/null 2>&1)
  fi

  # One shell per use case, so `echo $?` reports the status of the line before it.
  cat > "$shim/driver.sh" <<'DRIVER'
status=0
while IFS= read -r line; do
  printf '\033[2m$\033[0m %s\n' "$line"
  (exit "$status")
  eval "$line" 2>&1
  status=$?
done
DRIVER
  (cd "$work" && PATH="$shim:$PATH" CLICOLOR_FORCE=1 bash "$shim/driver.sh" < "$dir/cmds") > "$dir/transcript.ansi" 2>&1
  # Drop the throwaway directory name from messages.
  real="$(cd "$work" && pwd -P)"
  sed -i.bak "s|$real/||g; s|$work/||g" "$dir/transcript.ansi" && rm -f "$dir/transcript.ansi.bak"
  rm -rf "$work"
done
