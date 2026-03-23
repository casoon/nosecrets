//! Integration tests for secret detection rules
//!
//! These tests verify that each rule correctly detects its target secrets.
//! Note: Some tests (Stripe, Slack, Twilio) are omitted to avoid triggering
//! GitHub's push protection, even with obviously fake tokens.

use nosecrets_core::Detector;
use nosecrets_filter::{EntropyConfig, Filter};
use nosecrets_rules::load_builtin_rules;
use std::fs;
use tempfile::tempdir;

fn create_detector() -> Detector {
    let rules = load_builtin_rules().expect("failed to load rules");
    let filter = Filter::from_config(None, Vec::new()).expect("failed to create filter");
    Detector::new(rules, filter).expect("failed to create detector")
}

fn create_detector_with_entropy(config: EntropyConfig) -> Detector {
    let rules = load_builtin_rules().expect("failed to load rules");
    let filter = Filter::from_config(None, Vec::new()).expect("failed to create filter");
    Detector::with_entropy(rules, filter, config).expect("failed to create detector")
}

fn scan_content(detector: &Detector, content: &str) -> Vec<String> {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("test.txt");
    fs::write(&path, content).expect("write");
    let findings = detector.scan_files(dir.path(), &[path]).expect("scan");
    findings.into_iter().map(|f| f.rule_id).collect()
}

// ============================================================================
// AWS Tests
// ============================================================================

#[test]
fn detects_aws_secret_key() {
    let detector = create_detector();
    let content = r#"AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"aws-secret-key".to_string()),
        "expected aws-secret-key, got {:?}",
        rule_ids
    );
}

#[test]
fn skips_aws_access_key_example() {
    let detector = create_detector();
    // EXAMPLE suffix should be allowed
    let content = r#"AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"aws-access-key".to_string()),
        "EXAMPLE key should be skipped"
    );
}

#[test]
fn detects_aws_access_key_real() {
    let detector = create_detector();
    // Real-looking key without EXAMPLE
    let content = r#"AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7TESTING""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"aws-access-key".to_string()),
        "expected aws-access-key, got {:?}",
        rule_ids
    );
}

// ============================================================================
// GitHub Tests
// ============================================================================

#[test]
fn detects_github_pat_classic() {
    let detector = create_detector();
    let content = r#"GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx00""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"github-pat".to_string()),
        "expected github-pat, got {:?}",
        rule_ids
    );
}

#[test]
fn detects_github_fine_grained_pat() {
    let detector = create_detector();
    let content = r#"GITHUB_TOKEN = "github_pat_11XXXXXXXX0000000000_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"github-fine-grained-pat".to_string()),
        "expected github-fine-grained-pat, got {:?}",
        rule_ids
    );
}

// ============================================================================
// npm Tests
// ============================================================================

#[test]
fn detects_npm_token() {
    let detector = create_detector();
    let content = r#"NPM_TOKEN = "npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"npm-token".to_string()),
        "expected npm-token, got {:?}",
        rule_ids
    );
}

// ============================================================================
// Database URL Tests
// ============================================================================

#[test]
fn detects_postgres_url() {
    let detector = create_detector();
    let content = r#"DATABASE_URL = "postgresql://user:p4ssw0rd@localhost:5432/mydb""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"postgres-connection-uri".to_string()),
        "expected postgres-connection-uri, got {:?}",
        rule_ids
    );
}

#[test]
fn detects_mysql_url() {
    let detector = create_detector();
    let content = r#"DATABASE_URL = "mysql://admin:secretpass123@db.example.com/production""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"mysql-connection-uri".to_string()),
        "expected mysql-connection-uri, got {:?}",
        rule_ids
    );
}

// ============================================================================
// Private Key Tests
// ============================================================================

#[test]
fn detects_private_key() {
    let detector = create_detector();
    let content = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----"#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"private-key".to_string()),
        "expected private-key, got {:?}",
        rule_ids
    );
}

// ============================================================================
// GCP Tests
// ============================================================================

#[test]
fn detects_gcp_api_key() {
    let detector = create_detector();
    let content = r#"GCP_API_KEY = "AIzaSyA0123456789abcdefghijklmnopqrstuv""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"gcp-api-key".to_string()),
        "expected gcp-api-key, got {:?}",
        rule_ids
    );
}

// ============================================================================
// SendGrid Tests
// ============================================================================

#[test]
fn detects_sendgrid_api_key() {
    let detector = create_detector();
    let content = r#"SENDGRID_API_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"sendgrid-api-key".to_string()),
        "expected sendgrid-api-key, got {:?}",
        rule_ids
    );
}

// ============================================================================
// Twilio Tests
// ============================================================================

#[test]
fn detects_twilio_auth_token() {
    let detector = create_detector();
    let content = r#"TWILIO_AUTH_TOKEN = "aaaabbbbccccddddaaaabbbbccccdddd""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"twilio-auth-token".to_string()),
        "expected twilio-auth-token, got {:?}",
        rule_ids
    );
}

// Note: The following tests are commented out because GitHub's push protection
// blocks them even with obviously fake tokens:
// - detects_stripe_secret_key (sk_live_...)
// - detects_stripe_restricted_key (rk_live_...)
// - detects_slack_webhook (https://hooks.slack.com/...)
// - detects_slack_token (xoxb-...)
// - detects_twilio_api_key (SK...)
//
// These rules are tested manually and work correctly.

// ============================================================================
// High Entropy Detection Tests
// ============================================================================

#[test]
fn entropy_detects_unknown_token_in_env() {
    let detector = create_detector_with_entropy(EntropyConfig::default());
    let content = r#"SECRET_TOKEN="xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"high-entropy-string".to_string()),
        "should detect unknown high-entropy token, got {:?}",
        rule_ids
    );
}

#[test]
fn entropy_detects_bearer_like_token() {
    let detector = create_detector_with_entropy(EntropyConfig::default());
    let content = r#"Authorization: Bearer xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g"#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"high-entropy-string".to_string()),
        "should detect bearer-like high-entropy token, got {:?}",
        rule_ids
    );
}

#[test]
fn entropy_detects_proprietary_token_in_env() {
    let detector = create_detector_with_entropy(EntropyConfig::default());
    // Use a custom variable name that won't match generic-api-key regex
    let content = r#"MY_SECRET_CREDENTIAL="Rn4xZ8cW2qL7vM5bJ9yT3fK6gH1dP0sE""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        rule_ids.contains(&"high-entropy-string".to_string()),
        "should detect proprietary token, got {:?}",
        rule_ids
    );
}

#[test]
fn entropy_skips_uuid() {
    let detector = create_detector_with_entropy(EntropyConfig {
        require_context: false,
        ..EntropyConfig::default()
    });
    let content = r#"ID = "550e8400-e29b-41d4-a716-446655440000""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should not flag UUIDs"
    );
}

#[test]
fn entropy_skips_normal_hash() {
    let detector = create_detector_with_entropy(EntropyConfig {
        require_context: false,
        ..EntropyConfig::default()
    });
    // Pure hex string without secret context
    let content = r#"CHECKSUM = "a3f2b8c91d4e6f7890abcdef12345678""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should not flag pure hex hash without secret context"
    );
}

#[test]
fn entropy_skips_placeholder() {
    let detector = create_detector_with_entropy(EntropyConfig::default());
    let content = r#"SECRET_KEY="your_token_here_please_replace""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should not flag placeholder values"
    );
}

#[test]
fn entropy_skips_url_without_creds() {
    let detector = create_detector_with_entropy(EntropyConfig {
        require_context: false,
        ..EntropyConfig::default()
    });
    let content = r#"ENDPOINT = "https://api.example.com/v1/long/path/resource""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should not flag URLs without credentials"
    );
}

#[test]
fn entropy_skips_normal_english_text() {
    let detector = create_detector_with_entropy(EntropyConfig {
        require_context: false,
        ..EntropyConfig::default()
    });
    let content = r#"DESCRIPTION = "This is a normal English sentence that should not be flagged""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should not flag normal text"
    );
}

#[test]
fn entropy_requires_context_by_default() {
    let detector = create_detector_with_entropy(EntropyConfig::default());
    // High entropy but no secret-related context
    let content = r#"RANDOM_FIELD = "xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should require context by default"
    );
}

#[test]
fn entropy_no_duplicate_with_known_rule() {
    let detector = create_detector_with_entropy(EntropyConfig {
        require_context: false,
        ..EntropyConfig::default()
    });
    // AWS secret key - should be caught by regex rule, not duplicated by entropy
    let content = r#"AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY""#;
    let rule_ids = scan_content(&detector, content);
    let entropy_count = rule_ids
        .iter()
        .filter(|id| id.as_str() == "high-entropy-string")
        .count();
    assert_eq!(
        entropy_count, 0,
        "should not duplicate findings from regex rules"
    );
}

#[test]
fn entropy_disabled_produces_no_findings() {
    let detector = create_detector_with_entropy(EntropyConfig {
        enabled: false,
        ..EntropyConfig::default()
    });
    let content = r#"SECRET_TOKEN="xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should produce no entropy findings when disabled"
    );
}

#[test]
fn entropy_respects_min_length() {
    let detector = create_detector_with_entropy(EntropyConfig {
        min_length: 40,
        require_context: false,
        ..EntropyConfig::default()
    });
    // 32 chars - below min_length of 40
    let content = r#"TOKEN = "xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#;
    let rule_ids = scan_content(&detector, content);
    assert!(
        !rule_ids.contains(&"high-entropy-string".to_string()),
        "should respect min_length setting"
    );
}
