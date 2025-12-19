# nosecrets - Regel-Spezifikation

## Format

Regeln werden in TOML definiert.

## Felder

| Feld | Typ | Pflicht | Beschreibung |
|------|-----|---------|--------------|
| id | string | ja | Eindeutige ID |
| name | string | ja | Anzeigename |
| severity | string | ja | critical / high / medium / low |
| pattern | string | ja | Regex mit Capture Group |
| keywords | [string] | nein | Prefilter-Keywords |
| capture | int | nein | Capture Group Index (default: 1) |

### validate Block

| Feld | Typ | Beschreibung |
|------|-----|--------------|
| prefix | [string] | Erlaubte Präfixe |
| charset | string | Erlaubte Zeichen (Regex-Charset) |
| length | int | Exakte Länge |
| min_length | int | Minimale Länge |
| max_length | int | Maximale Länge |

### paths Block

| Feld | Typ | Beschreibung |
|------|-----|--------------|
| include | [string] | Nur diese Pfade (Glob) |
| exclude | [string] | Diese Pfade ignorieren (Glob) |

### allow Block

| Feld | Typ | Beschreibung |
|------|-----|--------------|
| patterns | [string] | Regex-Patterns die OK sind |
| values | [string] | Exakte Werte die OK sind |

## Beispiel

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
    exclude = ["test/", "docs/"]

    [rule.allow]
    patterns = ["EXAMPLE$", "SAMPLE$"]

## Severity Levels

| Level | Bedeutung | Exit Code |
|-------|-----------|-----------|
| critical | Sofort blockieren | 1 |
| high | Blockieren | 1 |
| medium | Warnung, blockieren | 1 |
| low | Nur Warnung | 0 (konfigurierbar) |

## Kategorien (geplant)

Regeln werden in Dateien organisiert:

    rules/
    ├── cloud.toml      # AWS, GCP, Azure, etc.
    ├── deploy.toml     # Vercel, Netlify, Fly.io, etc.
    ├── code.toml       # GitHub, GitLab, npm, etc.
    ├── payment.toml    # Stripe, PayPal, etc.
    ├── database.toml   # MongoDB, Redis, etc.
    ├── auth.toml       # JWT, OAuth, etc.
    ├── messaging.toml  # Slack, Discord, etc.
    └── generic.toml    # Private Keys, Passwords
