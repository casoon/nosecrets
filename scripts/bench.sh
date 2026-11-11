#!/usr/bin/env bash
# Reproducible benchmark for nosecrets: builds the release binary, generates a deterministic
# synthetic repository and measures the commands a user actually runs. Prints a Markdown table.
#
#   scripts/bench.sh
#
# Prerequisites: cargo, git, python3 and hyperfine (https://github.com/sharkdp/hyperfine,
# e.g. `brew install hyperfine` or `cargo install hyperfine`).
# Environment: BENCH_RUNS (runs per command, default 50), BENCH_FILES (default 2000).
#
# The repository holds BENCH_FILES text files (about 20 MB in total: source, configuration and
# lock-file-like content) and 20 planted fake secrets. It is generated from a fixed seed, so two
# runs scan identical bytes. The planted tokens are assembled at run time; none is a real credential.
set -euo pipefail

for tool in cargo git python3 hyperfine; do
  command -v "$tool" > /dev/null || { echo "missing prerequisite: $tool" >&2; exit 1; }
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
runs="${BENCH_RUNS:-50}"
files="${BENCH_FILES:-2000}"

cargo build --release --locked --quiet --manifest-path "$repo/Cargo.toml"
target="$(cargo metadata --format-version 1 --no-deps --manifest-path "$repo/Cargo.toml" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
bin="$target/release/nosecrets"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
corpus="$work/corpus"
mkdir -p "$corpus"

python3 - "$corpus" "$files" "$work/bytes" <<'PY'
import os, random, string, sys

root, count, bytes_file = sys.argv[1], int(sys.argv[2]), sys.argv[3]
written = 0
rng = random.Random(42)
words = ["config", "value", "handler", "request", "response", "buffer", "index", "client", "server",
         "parse", "render", "cache", "token_count", "retry", "timeout", "format", "stream", "queue"]
alnum = string.ascii_letters + string.digits

def ident():
    return "_".join(rng.choice(words) for _ in range(rng.randint(1, 3)))

def source_line():
    kind = rng.randint(0, 3)
    if kind == 0:
        return f"def {ident()}({ident()}, {ident()}):"
    if kind == 1:
        return f"    {ident()} = {ident()}({rng.randint(0, 9999)}, \"{ident()}\")"
    if kind == 2:
        return f"    return {ident()}[{rng.randint(0, 99)}] + {rng.randint(0, 99)}"
    return f"# {ident()} {ident()} {ident()}"

def config_line():
    return f"{ident()} = \"{ident()}-{rng.randint(0, 99999)}\""

def lock_line():
    digest = "".join(rng.choice(alnum + "+/") for _ in range(86))
    return f"  integrity sha512-{digest}=="

makers = [source_line, config_line, lock_line]
size = 10_000  # bytes per file, 2000 files give about 20 MB
for i in range(count):
    directory = os.path.join(root, f"pkg{i % 40:02d}", f"mod{i % 7}")
    os.makedirs(directory, exist_ok=True)
    make = makers[i % 3]
    lines, total = [], 0
    while total < size:
        line = make()
        lines.append(line)
        total += len(line) + 1
    text = "\n".join(lines) + "\n"
    written += len(text)
    with open(os.path.join(directory, f"file{i:04d}.txt"), "w") as handle:
        handle.write(text)

# 20 planted fake secrets, assembled from parts so this script holds no complete token.
for i in range(20):
    body = "".join(rng.choice(alnum) for _ in range(36))
    path = os.path.join(root, f"pkg{i:02d}", "mod0", f"file{i * 3:04d}.txt")
    with open(path, "a") as handle:
        handle.write("GITHUB_TOKEN = \"" + "ghp" + "_" + body + "\"\n")

with open(bytes_file, "w") as handle:
    handle.write(str(written))
PY

git -C "$corpus" init -q
git -C "$corpus" add -A
git -C "$corpus" -c user.name=bench -c user.email=bench@example.com commit -q -m "corpus"

results="$work/results"
mkdir -p "$results"
cd "$corpus"

measure() { # name, command...
  local name="$1"
  shift
  hyperfine --warmup 5 --runs "$runs" --style none --shell none --ignore-failure \
    --export-json "$results/$name.json" -- "$*" > /dev/null
}

measure startup "$bin --version"
# Nothing staged: the fixed cost every commit pays (regex compilation, git calls).
measure staged-none "$bin scan --staged --dry-run"
for i in $(seq 1 10); do
  printf 'touched = "line %s"\n' "$i" >> "pkg0$((i % 10))/mod1/file$(printf '%04d' $((i * 3 + 1))).txt"
done
git add -A
measure staged-10 "$bin scan --staged --dry-run"
measure tracked "$bin scan --tracked --dry-run"
measure path "$bin scan . --dry-run"

cpu="$( (sysctl -n machdep.cpu.brand_string 2> /dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2) | sed 's/^ *//')"
cores="$( (sysctl -n hw.ncpu 2> /dev/null || nproc) | head -1)"

python3 - "$results" "$files" "$(cat "$work/bytes")" "$("$bin" --version)" "$(hyperfine --version)" "$(uname -sr)" "$cpu" "$cores" "$runs" "$(uptime | sed 's/.*load averages*: *//' | cut -d" " -f1 | tr -d ,)" <<'PY'
import json, sys

results, files, size, version, hyperfine, system, cpu, cores, runs, load = sys.argv[1:11]
rows = [
    ("startup", "`nosecrets --version`"),
    ("staged-none", "`scan --staged`, nothing staged (fixed cost per commit)"),
    ("staged-10", "`scan --staged`, 10 changed files"),
    ("tracked", "`scan --tracked`, whole repository"),
    ("path", "`scan .`, working tree"),
]
print(f"{version}, {hyperfine}; {cpu}, {cores} cores, {system}; load average at start {load}.")
print(f"Repository: {files} files, about {int(size) / 1e6:.0f} MB, 20 planted fake secrets; {runs} runs per command after 5 warm-up runs.")
print()
print("| Command | Median | Mean | Std. dev. | Min | Max |")
print("|---|---|---|---|---|---|")
for key, label in rows:
    result = json.load(open(f"{results}/{key}.json"))["results"][0]
    # hyperfine 1.x puts the statistics on the result, 2.x under summary.time_wall_clock.
    stats = result if "mean" in result else result["summary"]["time_wall_clock"]
    ms = lambda value: f"{value * 1000:.1f} ms"
    print(f"| {label} | {ms(stats['median'])} | {ms(stats['mean'])} | {ms(stats['stddev'])} | {ms(stats['min'])} | {ms(stats['max'])} |")
PY
