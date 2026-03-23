use std::collections::HashMap;

use regex::Regex;

use nosecrets_filter::EntropyConfig;

/// A candidate token extracted from file content for entropy analysis.
#[derive(Debug, Clone)]
pub struct EntropyCandidate {
    pub text: String,
    pub byte_offset: usize,
    pub context_name: Option<String>,
}

/// A confirmed high-entropy match.
#[derive(Debug, Clone)]
pub struct EntropyMatch {
    pub text: String,
    pub byte_offset: usize,
}

/// Compute Shannon entropy (bits per character) for the given string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    freq.values().fold(0.0, |entropy, &count| {
        let p = count as f64 / len;
        entropy - p * p.log2()
    })
}

/// Context keywords that indicate a value is likely a secret.
const CONTEXT_KEYWORDS: &[&str] = &[
    "secret",
    "token",
    "key",
    "auth",
    "password",
    "passwd",
    "credential",
    "bearer",
    "authorization",
    "api_key",
    "apikey",
    "api-key",
    "private",
    "access_token",
    "refresh_token",
];

/// Placeholder values that should never be flagged.
const PLACEHOLDER_PATTERNS: &[&str] = &[
    "example",
    "changeme",
    "your_token",
    "your-token",
    "insert_here",
    "insert-here",
    "replace_me",
    "replace-me",
    "todo",
    "fixme",
    "placeholder",
    "xxxxxxxx",
    "test1234",
    "password123",
    "dummy",
    "sample",
    "mock",
];

/// Run entropy-based detection on file content.
/// Returns matches that passed all guards.
pub fn detect_entropy(
    text: &str,
    config: &EntropyConfig,
    allow_patterns: &[Regex],
) -> Vec<EntropyMatch> {
    if !config.enabled {
        return Vec::new();
    }

    let candidates = extract_candidates(text, config.min_length);
    let mut matches = Vec::new();

    for candidate in candidates {
        if !passes_guards(&candidate, config, allow_patterns) {
            continue;
        }
        let entropy = shannon_entropy(&candidate.text);
        if entropy < config.threshold {
            continue;
        }
        matches.push(EntropyMatch {
            text: candidate.text,
            byte_offset: candidate.byte_offset,
        });
    }

    matches
}

/// Extract candidate tokens from text.
/// Looks for quoted strings and assignment values.
fn extract_candidates(text: &str, min_length: usize) -> Vec<EntropyCandidate> {
    let mut candidates = Vec::new();
    let mut seen_offsets = std::collections::HashSet::new();

    // Pass 1: Quoted strings (double, single, backtick)
    extract_quoted_strings(text, min_length, &mut candidates, &mut seen_offsets);

    // Pass 2: Assignment values (key=value, key: value, .env style)
    extract_assignment_values(text, min_length, &mut candidates, &mut seen_offsets);

    candidates
}

/// Extract strings enclosed in quotes.
fn extract_quoted_strings(
    text: &str,
    min_length: usize,
    candidates: &mut Vec<EntropyCandidate>,
    seen: &mut std::collections::HashSet<usize>,
) {
    for quote in ['"', '\'', '`'] {
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == quote as u8 {
                let start = i + 1;
                let mut end = start;
                // Walk to closing quote, respecting backslash escapes
                while end < bytes.len() {
                    if bytes[end] == b'\\' && end + 1 < bytes.len() {
                        end += 2;
                        continue;
                    }
                    if bytes[end] == quote as u8 {
                        break;
                    }
                    end += 1;
                }
                if end < bytes.len() && end > start {
                    let inner = &text[start..end];
                    // Split on delimiters and check sub-tokens
                    add_subtokens(inner, start, min_length, text, candidates, seen);
                    i = end + 1;
                    continue;
                }
            }
            i += 1;
        }
    }
}

/// Extract values from assignment patterns like KEY=VALUE or KEY: VALUE.
fn extract_assignment_values(
    text: &str,
    min_length: usize,
    candidates: &mut Vec<EntropyCandidate>,
    seen: &mut std::collections::HashSet<usize>,
) {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Try KEY=VALUE (unquoted)
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let val = trimmed[eq_pos + 1..].trim();
            // Skip if value is quoted (already handled by quoted string extraction)
            if !val.starts_with('"') && !val.starts_with('\'') && !val.starts_with('`') {
                let line_byte_offset = byte_offset_of_line(text, trimmed);
                let val_offset = line_byte_offset
                    + eq_pos
                    + 1
                    + (trimmed[eq_pos + 1..].len() - trimmed[eq_pos + 1..].trim_start().len());
                add_subtokens(val, val_offset, min_length, text, candidates, seen);
                // Also store context from key
                if !val.is_empty() {
                    update_context_from_key(key, val_offset, candidates);
                }
            } else {
                // Value is quoted, update context for the quoted candidates near this line
                let key = key.to_string();
                let line_byte_offset = byte_offset_of_line(text, trimmed);
                update_context_from_key_for_line(
                    &key,
                    line_byte_offset,
                    line_byte_offset + trimmed.len(),
                    candidates,
                );
            }
        }

        // Try KEY: VALUE (YAML/config style) - only if no = found
        if trimmed.find('=').is_none() {
            if let Some(colon_pos) = trimmed.find(':') {
                let key = trimmed[..colon_pos].trim();
                let val = trimmed[colon_pos + 1..].trim();
                if !val.starts_with('"') && !val.starts_with('\'') && !val.starts_with('`') {
                    let line_byte_offset = byte_offset_of_line(text, trimmed);
                    let val_offset = line_byte_offset
                        + colon_pos
                        + 1
                        + (trimmed[colon_pos + 1..].len()
                            - trimmed[colon_pos + 1..].trim_start().len());
                    add_subtokens(val, val_offset, min_length, text, candidates, seen);
                    if !val.is_empty() {
                        update_context_from_key(key, val_offset, candidates);
                    }
                } else {
                    let key = key.to_string();
                    let line_byte_offset = byte_offset_of_line(text, trimmed);
                    update_context_from_key_for_line(
                        &key,
                        line_byte_offset,
                        line_byte_offset + trimmed.len(),
                        candidates,
                    );
                }
            }
        }
    }
}

/// Split a string on common delimiters and add sub-tokens as candidates.
fn add_subtokens(
    value: &str,
    base_offset: usize,
    min_length: usize,
    full_text: &str,
    candidates: &mut Vec<EntropyCandidate>,
    seen: &mut std::collections::HashSet<usize>,
) {
    // First, add the whole value if it qualifies
    if value.len() >= min_length && !seen.contains(&base_offset) {
        // Determine context from surrounding text
        let context = extract_context_from_surroundings(full_text, base_offset);
        seen.insert(base_offset);
        candidates.push(EntropyCandidate {
            text: value.to_string(),
            byte_offset: base_offset,
            context_name: context,
        });
    }

    // Split on delimiters and add sub-tokens
    let mut current_start = 0;
    for (i, ch) in value.char_indices() {
        if matches!(ch, ' ' | ',' | ';' | '&') {
            let token = &value[current_start..i];
            let token_offset = base_offset + current_start;
            if token.len() >= min_length && !seen.contains(&token_offset) {
                let context = extract_context_from_surroundings(full_text, token_offset);
                seen.insert(token_offset);
                candidates.push(EntropyCandidate {
                    text: token.to_string(),
                    byte_offset: token_offset,
                    context_name: context,
                });
            }
            current_start = i + ch.len_utf8();
        }
    }
    // Trailing token
    if current_start > 0 && current_start < value.len() {
        let token = &value[current_start..];
        let token_offset = base_offset + current_start;
        if token.len() >= min_length && !seen.contains(&token_offset) {
            let context = extract_context_from_surroundings(full_text, token_offset);
            seen.insert(token_offset);
            candidates.push(EntropyCandidate {
                text: token.to_string(),
                byte_offset: token_offset,
                context_name: context,
            });
        }
    }
}

/// Look at surrounding text to find a context keyword (variable name, header, etc.)
fn previous_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn lookback_char_boundary(text: &str, offset: usize, char_count: usize) -> usize {
    let mut index = previous_char_boundary(text, offset);
    for _ in 0..char_count {
        if index == 0 {
            break;
        }
        index = previous_char_boundary(text, index - 1);
    }
    index
}

fn extract_context_from_surroundings(text: &str, offset: usize) -> Option<String> {
    let safe_offset = previous_char_boundary(text, offset);
    // Look backwards up to 120 chars for context.
    let lookback = lookback_char_boundary(text, safe_offset, 120);
    let before = &text[lookback..safe_offset];
    // Find the start of the current line
    let line_start = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
    let line_prefix = &before[line_start..];
    let lower = line_prefix.to_lowercase();

    for keyword in CONTEXT_KEYWORDS {
        if lower.contains(keyword) {
            return Some(keyword.to_string());
        }
    }
    None
}

fn byte_offset_of_line(full_text: &str, line: &str) -> usize {
    line.as_ptr() as usize - full_text.as_ptr() as usize
}

fn update_context_from_key(key: &str, val_offset: usize, candidates: &mut [EntropyCandidate]) {
    let lower_key = key.to_lowercase();
    for keyword in CONTEXT_KEYWORDS {
        if lower_key.contains(keyword) {
            // Update any candidates at or near this offset
            for c in candidates.iter_mut() {
                if c.byte_offset == val_offset && c.context_name.is_none() {
                    c.context_name = Some(keyword.to_string());
                }
            }
            return;
        }
    }
}

fn update_context_from_key_for_line(
    key: &str,
    line_start: usize,
    line_end: usize,
    candidates: &mut [EntropyCandidate],
) {
    let lower_key = key.to_lowercase();
    for keyword in CONTEXT_KEYWORDS {
        if lower_key.contains(keyword) {
            for c in candidates.iter_mut() {
                if c.byte_offset >= line_start
                    && c.byte_offset <= line_end
                    && c.context_name.is_none()
                {
                    c.context_name = Some(keyword.to_string());
                }
            }
            return;
        }
    }
}

// =============================================================================
// Guards: filter out false positives
// =============================================================================

fn passes_guards(
    candidate: &EntropyCandidate,
    config: &EntropyConfig,
    allow_patterns: &[Regex],
) -> bool {
    let text = &candidate.text;

    // Length guard
    if text.len() < config.min_length {
        return false;
    }

    // User-configured allow patterns
    for pattern in allow_patterns {
        if pattern.is_match(text) {
            return false;
        }
    }

    // Placeholder guard
    let lower = text.to_lowercase();
    for placeholder in PLACEHOLDER_PATTERNS {
        if lower.contains(placeholder) {
            return false;
        }
    }

    // UUID guard: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    if is_uuid(text) {
        return false;
    }

    // Pure hex string guard (without secret context)
    if is_pure_hex(text) && candidate.context_name.is_none() {
        return false;
    }

    // File path guard
    if looks_like_path(text) {
        return false;
    }

    // URL without credentials guard
    if looks_like_url_without_creds(text) {
        return false;
    }

    // Import/require guard
    if looks_like_import(text) {
        return false;
    }

    // CSS class guard
    if looks_like_css(text) {
        return false;
    }

    // Character diversity guard: require at least 3 char groups
    if char_group_count(text) < 3 {
        return false;
    }

    // Only-lowercase guard: reject pure lowercase alpha strings
    if text.chars().all(|c| c.is_ascii_lowercase()) {
        return false;
    }

    // Context requirement
    if config.require_context && candidate.context_name.is_none() {
        return false;
    }

    true
}

fn is_uuid(s: &str) -> bool {
    // Standard UUID: 8-4-4-4-12 hex with dashes
    if s.len() == 36 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
        {
            return s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        }
    }
    false
}

fn is_pure_hex(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_path(s: &str) -> bool {
    // File paths typically contain / or \ and common extensions
    if (s.contains('/') || s.contains('\\'))
        && (s.starts_with('/') || s.starts_with("./") || s.starts_with("../") || s.contains("://"))
    {
        return true;
    }
    // Node-style module paths
    if s.starts_with('@') && s.contains('/') {
        return true;
    }
    false
}

fn looks_like_url_without_creds(s: &str) -> bool {
    if s.starts_with("http://") || s.starts_with("https://") {
        // If it contains user:pass@ it might have creds - don't filter
        if s.contains('@') {
            return false;
        }
        return true;
    }
    false
}

fn looks_like_import(s: &str) -> bool {
    // Common import patterns
    s.starts_with("import ")
        || s.starts_with("from ")
        || s.starts_with("require(")
        || s.starts_with("use ")
}

fn looks_like_css(s: &str) -> bool {
    // CSS class-like patterns: contain only lowercase, digits, dashes
    if s.len() < 20 {
        return false;
    }
    // Heuristic: lots of dashes + only lowercase/digits/dashes
    let dashes = s.chars().filter(|&c| c == '-').count();
    dashes >= 3
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Count character groups present: lowercase, uppercase, digits, special.
fn char_group_count(s: &str) -> usize {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;
    for c in s.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }
    has_lower as usize + has_upper as usize + has_digit as usize + has_special as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        // 8 distinct characters, each appearing once -> log2(8) = 3.0
        let entropy = shannon_entropy("abcdefgh");
        assert!((entropy - 3.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_single_char() {
        let entropy = shannon_entropy("aaaaaaa");
        assert!((entropy - 0.0).abs() < 0.01);
    }

    #[test]
    fn test_shannon_entropy_high() {
        // A longer random-looking token should have high entropy
        let entropy = shannon_entropy("aB3kL9mN2pQ5rT8wX1zA4cE7fG0hJ6iK");
        assert!(entropy > 4.0, "entropy was {}", entropy);
    }

    #[test]
    fn test_is_uuid() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_uuid("550e8400e29b41d4a716446655440000"));
        assert!(!is_uuid("not-a-uuid-at-all"));
    }

    #[test]
    fn test_is_pure_hex() {
        assert!(is_pure_hex("0123456789abcdef0123"));
        assert!(is_pure_hex("ABCDEF0123456789ABCD"));
        assert!(!is_pure_hex("0123456789abcdefghij"));
        assert!(!is_pure_hex("short"));
    }

    #[test]
    fn test_char_group_count() {
        assert_eq!(char_group_count("abcdef"), 1);
        assert_eq!(char_group_count("abcDEF"), 2);
        assert_eq!(char_group_count("abcDEF123"), 3);
        assert_eq!(char_group_count("abcDEF123!"), 4);
    }

    #[test]
    fn test_placeholder_rejection() {
        let config = EntropyConfig::default();
        let candidate = EntropyCandidate {
            text: "your_token_here_abcdefghijk".to_string(),
            byte_offset: 0,
            context_name: Some("token".to_string()),
        };
        assert!(!passes_guards(&candidate, &config, &[]));
    }

    #[test]
    fn test_uuid_rejection() {
        let config = EntropyConfig::default();
        let candidate = EntropyCandidate {
            text: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            byte_offset: 0,
            context_name: Some("key".to_string()),
        };
        assert!(!passes_guards(&candidate, &config, &[]));
    }

    #[test]
    fn test_context_required() {
        let config = EntropyConfig {
            require_context: true,
            ..EntropyConfig::default()
        };
        // High entropy, passes other guards, but no context
        let candidate = EntropyCandidate {
            text: "aB3kL9mN2pQ5rT8wX1zA4".to_string(),
            byte_offset: 0,
            context_name: None,
        };
        assert!(!passes_guards(&candidate, &config, &[]));
    }

    #[test]
    fn test_high_entropy_token_with_context_passes() {
        let config = EntropyConfig::default();
        let candidate = EntropyCandidate {
            text: "aB3kL9mN2pQ5rT8wX1zA4".to_string(),
            byte_offset: 0,
            context_name: Some("token".to_string()),
        };
        assert!(passes_guards(&candidate, &config, &[]));
    }

    #[test]
    fn test_detect_entropy_env_file() {
        let content = r#"SECRET_TOKEN="xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#;
        let config = EntropyConfig::default();
        let matches = detect_entropy(content, &config, &[]);
        assert!(
            !matches.is_empty(),
            "should detect high-entropy token in .env-style assignment"
        );
    }

    #[test]
    fn test_detect_entropy_skips_normal_values() {
        let content = r#"NAME="John Smith"
URL="https://example.com/api/v1"
"#;
        let config = EntropyConfig::default();
        let matches = detect_entropy(content, &config, &[]);
        assert!(
            matches.is_empty(),
            "should not flag normal values, got {:?}",
            matches.iter().map(|m| &m.text).collect::<Vec<_>>()
        );
    }
    #[test]
    fn test_detect_entropy_skips_uuid() {
        let content = r#"ID = "550e8400-e29b-41d4-a716-446655440000""#;
        let config = EntropyConfig {
            require_context: false,
            ..EntropyConfig::default()
        };
        let matches = detect_entropy(content, &config, &[]);
        assert!(matches.is_empty(), "should not flag UUIDs");
    }

    #[test]
    fn test_extract_context_handles_unicode_boundaries() {
        let content = r#"prefix 法法法法法法法法法法法法法法法法法法法法 SECRET_TOKEN="xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#;
        let config = EntropyConfig::default();
        let result = std::panic::catch_unwind(|| detect_entropy(content, &config, &[]));
        assert!(result.is_ok(), "unicode context extraction should not panic");
        let matches = result.unwrap();
        assert!(
            !matches.is_empty(),
            "should still detect the high-entropy token with unicode nearby"
        );
    }
}

