# nosecrets

Performanter Secret-Scanner in Rust, fokussiert auf Pre-Commit Hooks.

## Kernprinzipien

1. **Nur Pre-Commit** - Kein Git-History-Scanning
2. **Offline** - Keine API-Calls, keine Verification
3. **Schnell** - <50ms für typische Commits
4. **Einfach** - Minimale Konfiguration

## Architektur

    nosecrets/
    ├── Cargo.toml
    ├── crates/
    │   ├── nosecrets-cli/        # CLI (clap)
    │   ├── nosecrets-core/       # Detection Engine
    │   ├── nosecrets-rules/      # Regel-Parser
    │   ├── nosecrets-filter/     # Ignore/Allow System
    │   └── nosecrets-report/     # Output-Formate
    ├── rules/                    # Default-Regeln (TOML)
    └── .pre-commit-hooks.yaml

## Detection Pipeline

    1. Regex-Match (Pattern)
    2. Strukturvalidierung (charset, length, prefix)
    3. Ignore/Allow Check
    4. Report oder Block

Keine Shannon-Entropie. Keine API-Verification.

## CLI

    # Pre-Commit (Default)
    nosecrets scan --staged

    # Dateien scannen
    nosecrets scan src/

    # Interaktiver Modus
    nosecrets scan --staged --interactive

    # Ignore hinzufuegen
    nosecrets ignore <hash>

## Konfiguration

### .nosecrets.toml

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

### .nosecretsignore

    # Format: Content-Hash (tool-generiert)
    nsi_a1b2c3d4e5f6
    nsi_b2c3d4e5f6a7:src/config.py

### Inline-Kommentar

    api_key = "sk_test_xxx"  # @nosecrets-ignore
    api_key = "sk_test_xxx"  # @nsi example key

## Regel-Format

    [[rule]]
    id = "aws-access-key"
    name = "AWS Access Key ID"
    severity = "critical"
    pattern = '''\b((?:AKIA|ABIA|ACCA|ASIA)[A-Z2-7]{16})\b'''
    keywords = ["akia", "abia", "acca", "asia"]
    capture = 1

    [rule.validate]
    prefix = ["AKIA", "ABIA", "ACCA", "ASIA"]
    charset = "A-Z2-7"
    length = 20

    [rule.paths]
    exclude = ["test/", "*.md"]

    [rule.allow]
    patterns = ["EXAMPLE$"]

## Rust Dependencies

- clap - CLI
- regex - Pattern Matching
- aho-corasick - Keyword Prefiltering
- serde/toml - Konfiguration
- rayon - Parallelisierung
- gix - Git (staged files)

## Performance-Ziele

- Startup: <20ms
- Scan: >200 MB/s
- Memory: <50 MB
