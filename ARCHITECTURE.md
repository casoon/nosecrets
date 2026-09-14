# nosecrets - Architektur

## Crates

### nosecrets-cli
- Entry Point
- Argument Parsing (clap)
- Exit Codes
- Interaktiver Modus

### nosecrets-core
- Detector Struct
- Aho-Corasick Prefiltering
- Regex Matching
- Strukturvalidierung (charset, length, prefix)

### nosecrets-rules
- TOML Parser
- Rule Struct
- Eingebettete Default-Regeln (compile-time)

### nosecrets-filter
- Pfad-Ignores
- Pattern-Allows
- .nosecretsignore Parser
- Inline-Kommentar Detection (@nosecrets-ignore, @nsi)

### nosecrets-report
- Finding Struct
- Fingerprint-Generierung (Content-Hash)
- Terminal Output (farbig)
- JSON Export

## Detection Pipeline

    Input: Staged Files / Pfade
            |
            v
    +------------------+
    | Pfad-Filter      |  <-- [ignore].paths
    +------------------+
            |
            v
    +------------------+
    | Keyword Prefilter|  <-- Aho-Corasick
    +------------------+
            |
            v
    +------------------+
    | Regex Match      |  <-- rule.pattern
    +------------------+
            |
            v
    +------------------+
    | Strukturvalidierung|  <-- rule.validate
    +------------------+       (charset, length, prefix)
            |
            v
    +------------------+
    | Allow Check      |  <-- rule.allow, [allow], .nosecretsignore
    +------------------+
            |
            v
    +------------------+
    | Inline Check     |  <-- @nosecrets-ignore, @nsi
    +------------------+
            |
            v
        Finding

## Fingerprint

Format: Content-Hash des Secrets

    nsi_<sha256(secret)[0:12]>

Optional mit Pfad:

    nsi_<hash>:<path-glob>

Generiert vom Tool, nicht manuell erstellt.

## Performance

| Metrik | Ziel |
|--------|------|
| Bereich | Implementierung |
|--------|-----------------|
| Regex Compile | Einmal beim Aufbau des Detectors |
| Normale Dateien | Vollstaendig gelesen, parallel pro Datei |
| Initialscan | Alle getrackten Index-Blobs via `scan --tracked` |
| Pre-Commit | Nur geaenderte Index-Blobs via `scan --staged` |
| Git-Inhalte | Gebuendelt via `git cat-file --batch` |
| Parallelisierung | rayon |

Konkrete Startup-, Durchsatz- und Speicherziele gelten erst als Zusage, sobald sie durch reproduzierbare Benchmarks in CI abgesichert sind.

## Datenfluss

    CLI
     |
     +-- parse args
     +-- load config (.nosecrets.toml)
     +-- load rules (builtin + custom)
     +-- load ignores (.nosecretsignore)
     |
     v
    Core
     |
     +-- collect files (alle/geaenderte Index-Blobs / Dateipfade)
     +-- parallel scan (rayon)
     |   +-- read file
     |   +-- prefilter (aho-corasick)
     |   +-- match rules
     |   +-- validate structure
     |   +-- check allows
     |   +-- check inline comments
     |
     v
    Report
     |
     +-- deduplicate findings
     +-- generate fingerprints
     +-- format output (terminal / json)
     +-- exit code
