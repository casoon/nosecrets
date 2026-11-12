//! Integration tests for secret detection rules
//!
//! These tests verify that each rule correctly detects its target secrets.
//! Note: Some tests (Stripe, Slack, Twilio) are omitted to avoid triggering
//! GitHub's push protection, even with obviously fake tokens.

use nosecrets_core::{load_builtin_rules, DecodeConfig, Detector, EntropyConfig, Filter, Finding};
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
    let path = dir.path().join("test.env");
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

#[test]
fn every_builtin_rule_has_a_detection_fixture() {
    let cases = vec![
        (
            "azure-storage-key",
            format!("azure storage key = \"{}\" ", "a".repeat(88)),
        ),
        ("digitalocean-token", format!("dop_v1_{}", "a1".repeat(32))),
        (
            "cloudflare-api-token",
            format!("cloudflare api token = \"{}\" ", "q1".repeat(20)),
        ),
        (
            "cloudflare-global-api-key",
            format!("cloudflare global key = \"a{}\" ", "1a".repeat(18)),
        ),
        (
            "cloudflare-origin-ca-key",
            format!("v1.0-{}-{}", "a1".repeat(12), "b2".repeat(73)),
        ),
        ("github-oauth", format!("gho_{}", "a1".repeat(18))),
        ("github-app", format!("ghu_{}", "b2".repeat(18))),
        ("gitlab-pat", format!("glpat-{}", "a1".repeat(10))),
        ("pypi-token", format!("pypi-{}", "a1".repeat(25))),
        (
            "slack-token",
            format!("xoxb-1234567890-1234567890-{}", "a1".repeat(12)),
        ),
        (
            "slack-webhook",
            format!(
                "https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/{}",
                "a1".repeat(12)
            ),
        ),
        (
            "discord-token",
            format!("discord = M{}.abcdef.{}", "a".repeat(23), "b".repeat(27)),
        ),
        (
            "discord-webhook",
            format!(
                "https://discord.com/api/webhooks/12345678901234567/{}",
                "a1".repeat(30)
            ),
        ),
        (
            "netlify-access-token",
            format!("netlify token = \"{}\" ", "q1".repeat(20)),
        ),
        ("flyio-access-token", format!("fo1_{}", "a".repeat(43))),
        (
            "heroku-api-key",
            "heroku api_key = \"12345678-1234-1234-1234-123456789abc\" ".to_string(),
        ),
        ("heroku-api-key-v2", format!("HRKU-AA{}", "a1".repeat(29))),
        (
            "vercel-token",
            format!("vercel token = \"{}\" ", "q1".repeat(10)),
        ),
        (
            "railway-token",
            format!("railway token = \"{}\" ", "q1".repeat(10)),
        ),
        (
            "render-api-key",
            format!("render api_key = \"{}\" ", "q1".repeat(10)),
        ),
        (
            "supabase-anon-key",
            format!(
                "supabase anon = \"{}.{}.{}\"",
                "a1".repeat(10),
                "b2".repeat(10),
                "c3".repeat(10)
            ),
        ),
        (
            "supabase-service-role-key",
            format!(
                "supabase service_role = \"{}.{}.{}\"",
                "d4".repeat(10),
                "e5".repeat(10),
                "f6".repeat(10)
            ),
        ),
        (
            "generic-secret",
            "client_secret = \"AbCdEfGh12345678\"".to_string(),
        ),
        (
            "password-assignment",
            "password = \"CorrectHorseBatteryStaple\"".to_string(),
        ),
        (
            "basic-auth",
            "Authorization = \"Basic dXNlcjpzZWNyZXQ=\"".to_string(),
        ),
        ("twilio-api-key", format!("SK{}", "a1".repeat(16))),
        ("mailchimp-api-key", format!("{}-us12", "a1".repeat(16))),
        ("mailgun-api-key", format!("key-{}", "a1".repeat(16))),
        (
            "mongodb-connection-uri",
            "mongodb://user:s3cur3value@db.example.invalid/app".to_string(),
        ),
        (
            "redis-connection-uri",
            "redis://user:s3cur3value@db.example.invalid/0".to_string(),
        ),
        (
            "mssql-connection-uri",
            "mssql://user:s3cur3value@db.example.invalid/app".to_string(),
        ),
        (
            "jdbc-password-param",
            "jdbc:postgresql://db.example.invalid/app?password=s3cur3value".to_string(),
        ),
        ("stripe-secret-key", format!("sk_live_{}", "a1".repeat(12))),
        (
            "stripe-restricted-key",
            format!("rk_live_{}", "a1".repeat(12)),
        ),
        (
            "stripe-webhook-secret",
            format!("whsec_{}", "a1".repeat(16)),
        ),
        (
            "paypal-client-secret",
            format!("paypal client secret = \"{}\" ", "q1".repeat(20)),
        ),
        ("square-access-token", format!("sq0atp-{}", "a1".repeat(11))),
        (
            "square-oauth-secret",
            format!("sq0csp-{}a", "a1".repeat(21)),
        ),
    ];

    let entropy = EntropyConfig {
        enabled: false,
        ..EntropyConfig::default()
    };
    let detector = create_detector_with_entropy(entropy);
    for (rule_id, content) in cases {
        let rule_ids = scan_content(&detector, &content);
        assert!(
            rule_ids.iter().any(|actual| actual == rule_id),
            "expected {rule_id} for {content:?}, got {rule_ids:?}"
        );
    }
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

// ============================================================================
// Overlapping rules
// ============================================================================

#[test]
fn specific_rule_wins_over_generic_rule_for_the_same_secret() {
    let detector = create_detector();
    // Assembled at runtime so the source file holds no token-shaped literal.
    let key = ["sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc"].concat();
    let findings = scan_content(&detector, &format!("STRIPE_API_KEY = \"{key}\"\n"));
    assert_eq!(findings, vec!["stripe-secret-key"]);
}

// ============================================================================
// Newer token formats: changed provider formats, AI provider keys, developer-tool tokens
// ============================================================================
//
// The fixtures are assembled at runtime from a prefix and a filler body, so that no complete
// token appears in the source (GitHub push protection would block it) and the formats stay
// visible in one place.

const ALNUM: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ";
const HEX: &str = "0a1b2c3d4e5f67890fedcba987654321";
const LETTERS: &str = "AbCdEfGhIjKlMnOpQrStUvWxYzaBcDeFgHiJkLmNoPqRsTuVwXyZ";
const WORD: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_aBcDeFgHiJkLmNoPqRsTuV";
const URLSAFE: &str = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-aBcDeFgHiJkLmNoPqRsTuV";

fn fill(len: usize, set: &str) -> String {
    set.chars().cycle().skip(3).take(len).collect()
}

fn assert_rule_detects(rule_id: &str, token: &str) {
    let detector = create_detector();
    let rule_ids = scan_content(&detector, &format!("SERVICE_KEY = \"{token}\"\n"));
    assert!(
        rule_ids.iter().any(|id| id == rule_id),
        "expected {rule_id} for a token of {} characters, got {rule_ids:?}",
        token.len()
    );
}

fn assert_rule_ignores(rule_id: &str, token: &str) {
    let detector = create_detector();
    let rule_ids = scan_content(&detector, &format!("SERVICE_KEY = \"{token}\"\n"));
    assert!(
        !rule_ids.iter().any(|id| id == rule_id),
        "{rule_id} must not fire on {token:?}, got {rule_ids:?}"
    );
}

#[test]
fn detects_github_app_tokens_in_both_formats() {
    // Legacy: 40 characters.
    assert_rule_detects("github-app", &format!("ghu_{}", fill(36, ALNUM)));
    assert_rule_detects("github-app", &format!("ghs_{}", fill(36, ALNUM)));
    // Since October 2026: ghs_<app id>_<JWT>, about 520 characters with `_` and `.`.
    let jwt = format!(
        "{}.{}.{}",
        fill(170, URLSAFE),
        fill(220, URLSAFE),
        fill(80, URLSAFE)
    );
    assert_rule_detects("github-app", &format!("ghs_1234567_{jwt}"));
    assert_rule_ignores("github-app", &format!("ghs_{}", fill(20, ALNUM)));
}

#[test]
fn detects_routable_gitlab_tokens() {
    assert_rule_detects(
        "gitlab-pat-routable",
        &format!("glpat-{}.{}", fill(40, URLSAFE), "ab12cd34e"),
    );
    assert_rule_ignores(
        "gitlab-pat-routable",
        &format!("glpat-{}.abc", fill(10, ALNUM)),
    );
}

#[test]
fn detects_slack_app_and_configuration_tokens() {
    let app = format!("xapp-1-A0123BCDE45-1234567890123-{}", fill(64, HEX));
    assert_rule_detects("slack-app-config-token", &app);
    assert_rule_detects(
        "slack-app-config-token",
        &format!("xoxe.xoxp-1-{}", fill(165, ALNUM)),
    );
    assert_rule_detects(
        "slack-app-config-token",
        &format!("xoxe-1-{}", fill(146, ALNUM)),
    );
    assert_rule_ignores("slack-app-config-token", "xapp-1-short");
}

#[test]
fn detects_cloudflare_prefixed_tokens() {
    for prefix in ["cfk_", "cfut_", "cfat_", "cfoat_"] {
        assert_rule_detects(
            "cloudflare-prefixed-token",
            &format!("{prefix}{}", fill(46, ALNUM)),
        );
    }
    assert_rule_ignores(
        "cloudflare-prefixed-token",
        &format!("cfk_{}", fill(12, ALNUM)),
    );
    assert_rule_ignores(
        "cloudflare-prefixed-token",
        &format!("cfx_{}", fill(46, ALNUM)),
    );
}

#[test]
fn detects_vercel_prefixed_tokens() {
    for prefix in ["vcp_", "vci_", "vca_", "vcr_", "vck_"] {
        assert_rule_detects(
            "vercel-prefixed-token",
            &format!("{prefix}{}", fill(40, URLSAFE)),
        );
    }
    assert_rule_ignores("vercel-prefixed-token", &format!("vcp_{}", fill(8, ALNUM)));
    assert_rule_ignores(
        "vercel-prefixed-token",
        &format!("vcz_{}", fill(40, URLSAFE)),
    );
}

#[test]
fn detects_supabase_opaque_keys() {
    assert_rule_detects(
        "supabase-secret-key",
        &format!("sb_secret_{}", fill(30, URLSAFE)),
    );
    assert_rule_detects(
        "supabase-personal-access-token",
        &format!("sbp_{}", fill(40, "0123456789abcdefghijklmnopqrstuvwxyz")),
    );
    assert_rule_ignores(
        "supabase-secret-key",
        &format!("sb_publishable_{}", fill(30, URLSAFE)),
    );
    assert_rule_ignores(
        "supabase-personal-access-token",
        &format!("sbp_{}", fill(12, ALNUM)),
    );
}

#[test]
fn detects_ai_provider_keys() {
    let cases: Vec<(&str, String, String)> = vec![
        (
            "anthropic-api-key",
            format!("sk-ant-api03-{}AA", fill(93, URLSAFE)),
            format!("sk-ant-api03-{}", fill(12, URLSAFE)),
        ),
        (
            "anthropic-api-key",
            format!("sk-ant-admin01-{}AA", fill(93, URLSAFE)),
            format!("sk-ant-admin01-{}", fill(12, URLSAFE)),
        ),
        (
            "openai-api-key",
            format!("sk-proj-{}T3BlbkFJ{}", fill(58, URLSAFE), fill(58, URLSAFE)),
            format!("sk-proj-{}", fill(60, URLSAFE)),
        ),
        (
            "openai-api-key",
            format!("sk-{}T3BlbkFJ{}", fill(20, ALNUM), fill(20, ALNUM)),
            format!("sk-{}", fill(48, ALNUM)),
        ),
        (
            "huggingface-access-token",
            format!("hf_{}", fill(34, LETTERS)),
            format!("hf_{}", fill(20, LETTERS)),
        ),
        (
            "huggingface-access-token",
            format!("api_org_{}", fill(34, LETTERS)),
            format!("api_org_{}", fill(20, LETTERS)),
        ),
        (
            "groq-api-key",
            format!("gsk_{}", fill(52, ALNUM)),
            format!("gsk_{}", fill(30, ALNUM)),
        ),
        (
            "xai-api-key",
            format!("xai-{}", fill(80, WORD)),
            format!("xai-{}", fill(30, URLSAFE)),
        ),
        (
            "openrouter-api-key",
            format!("sk-or-v1-{}", fill(64, HEX)),
            format!("sk-or-v1-{}", fill(20, HEX)),
        ),
        (
            "replicate-api-token",
            format!("r8_{}", fill(37, URLSAFE)),
            format!("r8_{}", fill(20, URLSAFE)),
        ),
        (
            "perplexity-api-key",
            format!("pplx-{}", fill(48, ALNUM)),
            format!("pplx-{}", fill(20, ALNUM)),
        ),
    ];
    for (rule_id, positive, negative) in cases {
        assert_rule_detects(rule_id, &positive);
        assert_rule_ignores(rule_id, &negative);
    }
}

#[test]
fn detects_developer_tool_tokens() {
    let cases: Vec<(&str, String, String)> = vec![
        (
            "onepassword-service-account-token",
            format!("ops_eyJ{}", fill(260, ALNUM)),
            format!("ops_eyJ{}", fill(40, ALNUM)),
        ),
        (
            "dockerhub-token",
            format!("dckr_pat_{}", fill(27, URLSAFE)),
            format!("dckr_pat_{}", fill(10, URLSAFE)),
        ),
        (
            "dockerhub-token",
            format!("dckr_oat_{}", fill(32, URLSAFE)),
            format!("dckr_oat_{}", fill(10, URLSAFE)),
        ),
        (
            "sentry-user-token",
            format!("sntryu_{}", fill(64, HEX)),
            format!("sntryu_{}", fill(20, HEX)),
        ),
        (
            "sentry-org-token",
            format!("sntrys_eyJpYXQiO{}", fill(60, ALNUM)),
            "sntrys_eyJpYXQiO".to_string(),
        ),
        (
            "linear-api-key",
            format!("lin_api_{}", fill(40, ALNUM)),
            format!("lin_api_{}", fill(12, ALNUM)),
        ),
        (
            "notion-integration-token",
            format!("ntn_{}{}", "12345678901", fill(35, ALNUM)),
            format!("ntn_{}", fill(10, ALNUM)),
        ),
        (
            "postman-api-key",
            format!("PMAK-{}-{}", fill(24, HEX), fill(34, HEX)),
            format!("PMAK-{}", fill(10, HEX)),
        ),
        (
            "databricks-token",
            format!("dapi{}", fill(32, HEX)),
            format!("dapi{}", fill(10, HEX)),
        ),
        (
            "shopify-token",
            format!("shpat_{}", fill(32, HEX)),
            format!("shpat_{}", fill(10, HEX)),
        ),
        (
            "doppler-token",
            format!("dp.pt.{}", fill(43, ALNUM)),
            format!("dp.pt.{}", fill(10, ALNUM)),
        ),
    ];
    for (rule_id, positive, negative) in cases {
        assert_rule_detects(rule_id, &positive);
        assert_rule_ignores(rule_id, &negative);
    }
}

#[test]
fn telegram_bot_tokens_need_their_context() {
    let detector = create_detector();
    let token = format!("123456789:A{}", fill(34, URLSAFE));
    let with_context = scan_content(&detector, &format!("TELEGRAM_BOT_TOKEN = \"{token}\"\n"));
    assert!(
        with_context.iter().any(|id| id == "telegram-bot-token"),
        "expected telegram-bot-token, got {with_context:?}"
    );
    let without_context = scan_content(&detector, &format!("build_stamp = \"{token}\"\n"));
    assert!(
        !without_context.iter().any(|id| id == "telegram-bot-token"),
        "no context keyword, got {without_context:?}"
    );
}

#[test]
fn checksum_rules_accept_valid_and_reject_altered_tokens() {
    use nosecrets_core::parse_rules;
    // A custom rule with `validate.checksum`. The valid token is an example from a third-party
    // wiki that uses the 30 + 6 layout (prefix tk_), not a real credential.
    let rules = parse_rules(
        r#"
        [[rule]]
        id = "tk-token"
        name = "Example token with checksum"
        severity = "high"
        pattern = '''\b(tk_[A-Za-z0-9]{36})\b'''
        keywords = ["tk_"]

        [rule.validate]
        prefix = ["tk_"]
        checksum = "crc32-base62-suffix6"
        "#,
        "inline",
    )
    .expect("rules");
    let filter = Filter::from_config(None, Vec::new()).expect("filter");
    let detector = Detector::new(rules, filter).expect("detector");
    let valid = scan_content(
        &detector,
        "t = \"tk_GNrRoBa1p9nuwm7XrWkrhYUNQ7edOw4GUp8I\"\n",
    );
    assert!(valid.contains(&"tk-token".to_string()), "got {valid:?}");
    let altered = scan_content(
        &detector,
        "t = \"tk_GNrRoBa1p9nuwm7XrWkrhYUNQ7edOw4GUp8J\"\n",
    );
    assert!(
        !altered.contains(&"tk-token".to_string()),
        "got {altered:?}"
    );
}

// ============================================================================
// Base64-encoded secrets
// ============================================================================

fn b64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let acc = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(alphabet[(acc >> (18 - 6 * i) & 63) as usize] as char);
        }
        if pad {
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64(text: &str) -> String {
    b64_encode(text.as_bytes(), STANDARD, true)
}

fn fake_github_token() -> String {
    ["ghp", "_", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cD1fG3hJ5"].concat()
}

fn scan_findings(detector: &Detector, name: &str, content: &str) -> Vec<Finding> {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join(name);
    fs::write(&path, content).expect("write");
    detector.scan_files(dir.path(), &[path]).expect("scan")
}

#[test]
fn detects_base64_github_token_in_kubernetes_secret() {
    let detector = create_detector();
    let manifest = format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ci\ndata:\n  token: {}\n",
        b64(&fake_github_token())
    );
    let findings = scan_findings(&detector, "secret.yaml", &manifest);
    assert_eq!(findings.len(), 1, "got {findings:?}");
    let finding = &findings[0];
    assert_eq!(finding.rule_id, "github-pat");
    assert_eq!((finding.line, finding.column), (6, 10));
    assert_eq!(finding.encoding, Some("base64"));
    // Same secret, same fingerprint as the plain finding.
    let plain = scan_findings(
        &detector,
        "plain.env",
        &format!("T={}\n", fake_github_token()),
    );
    assert_eq!(plain.len(), 1, "got {plain:?}");
    assert_eq!(plain[0].fingerprint, finding.fingerprint);
    assert_eq!(plain[0].encoding, None);
}

#[test]
fn detects_base64_aws_key_pair_in_kubernetes_secret() {
    let detector = create_detector();
    let access = ["AKIA", "QWERTYUIOP23ASDF"].concat();
    let secret = ["wJalrXUtnFEMI", "/K7MDENG/", "bPxRfiCYTESTKEY123"].concat();
    let manifest = format!(
        "data:\n  id: {}\n  key: {}\n",
        b64(&access),
        b64(&format!("AWS_SECRET_ACCESS_KEY = \"{secret}\""))
    );
    let findings = scan_findings(&detector, "aws.yaml", &manifest);
    let find = |rule: &str| findings.iter().find(|f| f.rule_id == rule);
    assert_eq!(
        find("aws-access-key").map(|f| f.line),
        Some(2),
        "got {findings:?}"
    );
    assert_eq!(
        find("aws-secret-key").map(|f| f.line),
        Some(3),
        "got {findings:?}"
    );
    assert!(findings.iter().all(|f| f.encoding == Some("base64")));
}

#[test]
fn detects_url_safe_base64() {
    let detector = create_detector();
    // Pad the plain text so that the URL-safe alphabet really differs from the standard one.
    let text = format!("??>>{}??>>", fake_github_token());
    let encoded = b64_encode(text.as_bytes(), URL_SAFE, false);
    assert!(encoded.contains('-') || encoded.contains('_'));
    let findings = scan_findings(&detector, "ci.env", &format!("B64_TOKEN={encoded}\n"));
    let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert_eq!(ids, ["github-pat"], "got {findings:?}");
    assert_eq!(findings[0].encoding, Some("base64"));
}

#[test]
fn ignores_base64_png_header_and_random_bytes() {
    let detector = create_detector();
    let png = b64_encode(
        &[
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, b'I', b'H', b'D', b'R',
            0, 0, 1, 0, 0, 0, 1, 0, 8, 6,
        ],
        STANDARD,
        true,
    );
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let random: Vec<u8> = (0..48)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    let content = format!(
        "icon: {png}\nblob: {}\n",
        b64_encode(&random, STANDARD, true)
    );
    let findings = scan_findings(&detector, "data.yaml", &content);
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn base64_decoding_can_be_disabled() {
    let rules = load_builtin_rules().expect("rules");
    let filter = Filter::from_config(None, Vec::new()).expect("filter");
    let detector = Detector::new(rules, filter)
        .expect("detector")
        .with_decode(DecodeConfig { base64: false });
    let content = format!("data:\n  token: {}\n", b64(&fake_github_token()));
    let findings = scan_findings(&detector, "secret.yaml", &content);
    assert!(findings.is_empty(), "got {findings:?}");
}

#[test]
fn plain_secret_next_to_base64_text_is_reported_once() {
    let detector = create_detector();
    let content = format!(
        "token: {}\nnote: {}\n",
        fake_github_token(),
        b64("just some harmless configuration text")
    );
    let findings = scan_findings(&detector, "mixed.yaml", &content);
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].encoding, None);
    assert_eq!(findings[0].line, 1);
}

#[test]
fn encoded_secret_behind_a_generic_name_is_reported_by_its_own_rule() {
    let detector = create_detector();
    let content = format!("api_key: \"{}\"\n", b64(&fake_github_token()));
    let findings = scan_findings(&detector, "config.yaml", &content);
    assert_eq!(findings.len(), 1, "got {findings:?}");
    assert_eq!(findings[0].rule_id, "github-pat");
    assert_eq!(findings[0].encoding, Some("base64"));
    assert_eq!((findings[0].line, findings[0].column), (1, 11));
}

#[test]
fn inline_ignore_applies_to_base64_findings() {
    let detector = create_detector();
    let content = format!("token: {} # @nosecrets-ignore\n", b64(&fake_github_token()));
    let findings = scan_findings(&detector, "secret.yaml", &content);
    assert!(findings.is_empty(), "got {findings:?}");
}
