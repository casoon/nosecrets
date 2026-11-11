//! Corpus test for the entropy layer: identifiers, interpolation and type
//! signatures in a secret context are not reported; opaque tokens are.
//! All tokens are random-looking strings, not credentials of any provider.

use nosecrets_core::{load_builtin_rules, Detector, EntropyConfig, Filter};
use std::fs;
use tempfile::tempdir;

fn entropy_findings(line: &str) -> usize {
    let rules = load_builtin_rules().expect("failed to load rules");
    let filter = Filter::from_config(None, Vec::new()).expect("failed to create filter");
    let detector =
        Detector::with_entropy(rules, filter, EntropyConfig::default()).expect("detector");
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("sample.txt");
    fs::write(&path, format!("{line}\n")).expect("write");
    detector
        .scan_files(dir.path(), &[path])
        .expect("scan")
        .iter()
        .filter(|f| f.rule_id == "high-entropy-string")
        .count()
}

const NEGATIVE: &[&str] = &[
    r#"const token = getUserAuthenticationTokenFromRequest(request);"#,
    r#"auth_header = "getUserAuthenticationTokenFromRequest""#,
    r#"css_key = "background-color-primary-hover""#,
    r#"SECRET_NAME = "MAX_CONNECTION_RETRY_TIMEOUT""#,
    r#"token_class = "background-color-primary-hover-focus""#,
    r#"auth_method = "authenticateWithPasswordCredentials""#,
    r#"apiKeyHeaderName = "X_AUTHORIZATION_REQUEST_HEADER_NAME""#,
    r#"password_field = "confirmationPasswordInputElement""#,
    r#"secret_ref = "kubernetesSecretReferenceConfiguration""#,
    r#"api_key_env = "DEFAULT_APPLICATION_ENVIRONMENT_KEY""#,
    r#"private_key_path = "defaultPrivateKeyFileLocation""#,
    r#"auth_token_cache = "authenticationTokenCacheExpiration""#,
    r#"SECRET_KEY_BASE_NAME = "APPLICATION_SECRET_KEY_BASE_NAME""#,
    r#"refresh_token_key = "refresh-token-storage-key-name""#,
    r#"bearer_prefix = "AuthorizationBearerPrefixValue""#,
    r#"credential_provider = "defaultCredentialProviderChainFactory""#,
    r#"access_token_ttl = "accessTokenTimeToLiveInSeconds""#,
    r#"echo "CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN:-(not set)}""#,
    r#"headers: { Authorization: `Bearer ${env.R2_SQL_TOKEN}` }"#,
    r#"const secret = `${process.env.APPLICATION_SECRET_KEY_VALUE}`;"#,
    r#"export API_TOKEN=${DEPLOYMENT_API_TOKEN_FROM_VAULT}"#,
    r#"password: ${DATABASE_ADMIN_PASSWORD:-changeit-locally}"#,
    r#"token = os.environ["DEPLOYMENT_API_TOKEN_FROM_VAULT"]"#,
    r#"const key = config["application_secret_key_name"];"#,
    r#"secret = settings.vault["database_admin_password_ref"]"#,
    r#"api_key = request.headers["x-application-api-key-header"]"#,
    r#"fn token() -> `Promise<FlagshipEvaluationDetails<boolean>>`"#,
    r#"| authToken | `Promise<FlagshipEvaluationDetails<boolean>>` |"#,
    r#"const secretStore: Map<string, Result<SecretValue, VaultError>> = new Map();"#,
    r#"let auth: Option<Vec<AuthenticationTokenProvider>> = None;"#,
    r#"api_key_type = "Promise<ApplicationKeyResponse<string>>""#,
    r#"password_policy = "minimumPasswordLengthRequirement""#,
];

const POSITIVE: &[&str] = &[
    r#"SECRET_TOKEN="xK9mB2vL5nQ8rT3wA7jP1hD6fY4cE0g""#,
    r#"vendor_auth = "Zp3Qw8Lm1Vx6Nb4Tc9Rj2Hd7Fy5Ks0Ga""#,
    r#"AUTH_TOKEN=q7Wn2Xe9Rb4Ty6Uk1Ic8Op3As5Dh0Fj"#,
    r#"password: "Lk4Jh7Gf2Ds9Aq1Wz6Xc3Vb8Nm5Er0Ty""#,
    r#"upstream_token = "Mn8Bv3Cx6Zl1Ka4Sj7Hd2Gf9Pq5Wo0Ei""#,
    r#"const token = "Yt6Re2Wq9Uo4Ip7Lk1Jh5Gf8Ds3Az0Xc""#,
    r#"export SECRET_KEY=Bn5Vm8Cx2Zl7Ka3Sj9Hd4Gf1Pq6Wo0E"#,
    r#"Authorization: Bearer Hg7Jf2Kd9Sl4Aq1Pw6Oe3Ri8Uy5Tz0Xm"#,
    r#"private_key_id = "Cv9Bn4Mx1Zl6Ka8Sj3Hd7Gf2Pq5Wo0Ty""#,
    r#"refresh_token: Qa1Ws8Ed3Rf6Tg9Yh2Uj5Ik7Ol4Pz0Xc"#,
    r#"SESSION_TOKEN="Rt5Yu8Io2Pa6Sd9Fg1Hj4Kl7Zx3Cv0Bn""#,
    r#"access_token = "Ew3Qr7Ty1Ui9Op5As2Df8Gh6Jk4Lz0Xm""#,
    r#"webhook_auth = 'Zx8Cv2Bn5Mq9Wl3Ke6Rj1Th7Yg4Uf0Id'"#,
    r#"DB_PASSWORD=Pl6Ok9Ij2Uh5Yg8Tf1Rd4Es7Aw3Qz0Xs"#,
    r#"auth_key: "Mj4Nh7Bg1Vf9Cd2Xs6Za3Qw8Er5Ty0Ui""#,
    r#"api_token = "Kd9Fj2Hs7Lq4Pw1Ne6Rb3Tc8Vy5Xu0Za""#,
    r#"const key = "${PREFIX}_Gt8Hy3Ju6Ki1Lo9Mp4Nq7Rs2Vx5Wz0Ab""#,
    r#"api_token = os.environ["Hk7Jl2Gm9Fn4Dp1Sq6Ar3Wt8Ey5Uz0Xv"]"#,
];

#[test]
fn corpus_negative_lines_are_not_reported() {
    assert!(NEGATIVE.len() >= 30);
    let reported: Vec<&&str> = NEGATIVE
        .iter()
        .filter(|line| entropy_findings(line) > 0)
        .collect();
    assert!(reported.is_empty(), "false positives: {reported:#?}");
}

#[test]
fn corpus_positive_lines_are_reported() {
    assert!(POSITIVE.len() >= 15);
    let missed: Vec<&&str> = POSITIVE
        .iter()
        .filter(|line| entropy_findings(line) == 0)
        .collect();
    assert!(missed.is_empty(), "missed secrets: {missed:#?}");
}
