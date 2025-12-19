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
| Startup | <20ms |
| Scan | >200 MB/s |
| Memory | <50 MB |
| Regex Compile | Lazy (once_cell) |
| File Read | Memory-mapped fuer grosse Dateien |
| Parallelisierung | rayon |

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
     +-- collect files (git staged / paths)
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
