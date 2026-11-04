//! Integration tests for `authkestra_resource::jwt`, covering:
//! - multi-value audience support on `ValidationConfig` / `ValidationConfigBuilder`
//! - backward compatibility of the single-value `.audience(...)` builder method
//! - opt-in strict `kid` enforcement on `JwksCache`
//! - per-issuer JWKS resolution for a multi-issuer resource server (issue #243)
//! - the documented default values produced by `ValidationConfigBuilder`
//!
//! JWKS is served via a local `wiremock` server and tokens are signed with
//! freshly generated RSA keys so the full offline-validation path (JWKS fetch,
//! key lookup, signature + claim validation) is exercised end to end.

use authkestra_engine::strategy::AuthenticationStrategy;
use authkestra_engine::token::cert_binding::{x5t_s256_thumbprint, ClientCertificateDer};
use authkestra_engine::token::jwk::Jwk;
use authkestra_engine::token::DEFAULT_LEEWAY_SECS;
use authkestra_resource::jwt::{
    validate_jwt_generic, validate_jwt_with_resolver, IssuerTrustMap, JwksCache, JwtStrategy,
    ValidationConfig, ValidationError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header::AUTHORIZATION, Request};
use jsonwebtoken::{encode, errors::ErrorKind, Algorithm, EncodingKey, Header, Validation};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, Serialize, Deserialize)]
struct TestClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
}

#[derive(Serialize)]
struct JwksBody {
    keys: Vec<Jwk>,
}

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

/// Generates a fresh RSA key pair and wraps it as both a signing key and the
/// public `Jwk` representation that would be published on a JWKS endpoint.
fn generate_rsa_key(kid: Option<&str>) -> TestKey {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate RSA key");
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to encode PKCS8 PEM");
    let encoding_key =
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("failed to build encoding key");

    let n = URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be());

    // `use`/`key_ops` are left unset on purpose: that is the shape most IdPs
    // publish, so the existing tests keep exercising the permissive path.
    let mut jwk = Jwk::rsa(n, e).with_alg("RS256");
    if let Some(kid) = kid {
        jwk = jwk.with_kid(kid);
    }

    TestKey { encoding_key, jwk }
}

/// As [`generate_rsa_key`], but stamps RFC 7517 §4.2 `use` on the published
/// JWK — `"sig"` for a signing key, `"enc"` for an encryption key such as the
/// RSA-OAEP key a stock Keycloak realm serves alongside its signing key.
fn generate_rsa_key_for_use(kid: Option<&str>, key_use: &str) -> TestKey {
    let mut key = generate_rsa_key(kid);
    key.jwk.r#use = Some(key_use.to_string());
    key
}

fn sign_token<T: Serialize>(key: &EncodingKey, kid: Option<&str>, claims: &T) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = kid.map(|s| s.to_string());
    encode(&header, claims, key).expect("failed to sign token")
}

fn future_exp() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize
        + 3600
}

async fn start_jwks_server(keys: Vec<Jwk>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&JwksBody { keys }))
        .mount(&server)
        .await;
    server
}

fn jwks_url(server: &MockServer) -> String {
    format!("{}/.well-known/jwks.json", server.uri())
}

#[tokio::test]
async fn multi_audience_accepts_token_matching_any_configured_audience() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .audiences(["a", "b", "c"])
        .build();
    assert_eq!(
        config.audience,
        vec!["a".to_string(), "b".to_string(), "c".to_string()]
    );

    let cache = JwksCache::new(config.jwks_url.clone(), config.refresh_interval);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&config.audience);

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("b".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let result: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("token whose aud is in the configured audience set should validate");
    assert_eq!(result.sub, "user-1");
}

#[tokio::test]
async fn multi_audience_rejects_token_not_matching_any_configured_audience() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .audiences(["a", "c"])
        .build();

    let cache = JwksCache::new(config.jwks_url.clone(), config.refresh_interval);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&config.audience);

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("b".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("token whose aud is absent from the configured set must be rejected");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

#[test]
fn single_audience_builder_call_is_backward_compatible() {
    let config = ValidationConfig::builder()
        .jwks_url("https://example.invalid/jwks.json")
        .audience("x")
        .build();

    assert_eq!(config.audience, vec!["x".to_string()]);
}

#[tokio::test]
async fn single_audience_builder_validates_like_before() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .audience("x")
        .build();

    let cache = JwksCache::new(config.jwks_url.clone(), config.refresh_interval);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&config.audience);

    let matching = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("x".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &matching);
    validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect("token with matching single audience should validate");

    let mismatched = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: Some("y".to_string()),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &mismatched);
    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("token with mismatched single audience must be rejected");
    assert!(matches!(err, ValidationError::Jwt(_)));
}

// --- Issue #350: clock-skew leeway ---
//
// `ValidationConfig` inherited `jsonwebtoken`'s 60-second tolerance on `exp`
// with nothing naming it and no way to change it. It now carries the same
// `DEFAULT_LEEWAY_SECS` constant `TokenManager` uses, so the two halves of a
// deployment state the same tolerance instead of both borrowing one.

/// Signs a token whose `exp` is `seconds_ago` in the past.
fn expired_token(key: &TestKey, seconds_ago: usize) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    sign_token(
        &key.encoding_key,
        Some("kid-1"),
        &TestClaims {
            sub: "user-1".to_string(),
            exp: now - seconds_ago,
            aud: None,
        },
    )
}

fn validation_with_leeway(leeway: u64) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.leeway = leeway;
    validation
}

/// The builder defaults to the shared constant rather than to zero — the trap
/// a plain `u64` field on a `#[derive(Default)]` builder would have set.
#[test]
fn the_builder_defaults_leeway_to_the_shared_constant() {
    let config = ValidationConfig::builder()
        .jwks_url("https://idp.example.com/jwks")
        .build();
    assert_eq!(config.leeway, DEFAULT_LEEWAY_SECS);

    let configured = ValidationConfig::builder()
        .jwks_url("https://idp.example.com/jwks")
        .leeway(0)
        .build();
    assert_eq!(configured.leeway, 0);
}

/// The default tolerance accepts a token that has already expired...
#[tokio::test]
async fn a_token_expired_within_the_leeway_is_accepted() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));

    let token = expired_token(&key, 30);

    let validated: TestClaims =
        validate_jwt_generic(&token, &cache, &validation_with_leeway(DEFAULT_LEEWAY_SECS))
            .await
            .expect("the default tolerance should still accept this token");
    assert_eq!(validated.sub, "user-1");
}

/// ...and setting the leeway to zero is what makes expiry bite immediately.
#[tokio::test]
async fn leeway_zero_rejects_a_token_the_default_would_accept() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));

    let token = expired_token(&key, 5);

    // Precondition: this is a token the default would let through, so the
    // rejection below is attributable to the setting and nothing else.
    validate_jwt_generic::<TestClaims>(
        &token,
        &cache,
        &validation_with_leeway(DEFAULT_LEEWAY_SECS),
    )
    .await
    .expect("precondition: the default tolerance accepts this token");

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation_with_leeway(0))
        .await
        .expect_err("with no tolerance an expired token must be refused");
    assert!(
        matches!(&err, ValidationError::Jwt(e) if matches!(e.kind(), ErrorKind::ExpiredSignature)),
        "expected an expiry rejection, got: {err}"
    );
}

/// The wiring, end to end through `JwtStrategy`.
///
/// The two tests above build a `Validation` by hand, so they would still pass
/// if `build_validation` stopped copying `config.leeway` across. This one goes
/// through the strategy, which is the path an application actually takes, so
/// it fails if the config field is set but never applied.
#[tokio::test]
async fn the_strategy_applies_the_configured_leeway() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let token = expired_token(&key, 5);

    async fn authenticate(config: ValidationConfig, token: &str) -> bool {
        let strategy: JwtStrategy<TestClaims> = JwtStrategy::new(config);
        let request = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        matches!(strategy.authenticate(&parts).await, Ok(Some(_)))
    }

    let default_config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    assert!(
        authenticate(default_config, &token).await,
        "precondition: the default tolerance accepts a token expired 5s ago"
    );

    let strict_config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .leeway(0)
        .build();
    assert!(
        !authenticate(strict_config, &token).await,
        "leeway(0) was set on the config but never reached the Validation"
    );
}

#[tokio::test]
async fn the_strategy_validates_not_before_with_configured_leeway() {
    use authkestra_resource::jwt::SingleJwksResolver;

    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // `TestClaims` deliberately does not expose nbf: the decoder must validate
    // registered claims even when the application's identity type omits them.
    for (nbf, leeway, expected) in [
        (None, 0, true),
        (Some(serde_json::json!(now - 30)), 0, true),
        (
            Some(serde_json::json!(now + 300)),
            DEFAULT_LEEWAY_SECS,
            false,
        ),
        (Some(serde_json::json!(now + 30)), DEFAULT_LEEWAY_SECS, true),
        (Some(serde_json::json!(now + 30)), 0, false),
        (Some(serde_json::json!(now + 120)), 180, true),
        (Some(serde_json::json!("invalid")), 0, false),
    ] {
        let mut claims = serde_json::json!({"sub": "user-1", "iss": "issuer", "exp": now + 3600});
        if let Some(nbf) = nbf {
            claims["nbf"] = nbf;
        }
        let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

        for custom_resolver in [false, true] {
            let config = ValidationConfig::builder()
                .jwks_url(jwks_url(&server))
                .issuer("issuer")
                .leeway(leeway)
                .build();
            let strategy: JwtStrategy<TestClaims> = if custom_resolver {
                let cache = Arc::new(JwksCache::new(jwks_url(&server), Duration::from_secs(3600)));
                JwtStrategy::with_resolver(config, Box::new(SingleJwksResolver::new(cache)))
            } else {
                JwtStrategy::new(config)
            };
            let request = Request::builder()
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(())
                .unwrap();
            let (parts, _) = request.into_parts();
            let result = strategy
                .authenticate(&parts)
                .await
                .expect("authentication must not error");
            assert_eq!(
                result.is_some(),
                expected,
                "nbf={:?}, leeway={leeway}, custom_resolver={custom_resolver}",
                claims.get("nbf")
            );
        }
    }
}

#[tokio::test]
async fn missing_kid_falls_back_to_first_key_by_default() {
    let key1 = generate_rsa_key(Some("k1"));
    let key2 = generate_rsa_key(Some("k2"));
    let server = start_jwks_server(vec![key1.jwk.clone(), key2.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    // Signed by the FIRST key in the JWKS, with no `kid` header on the token.
    let token = sign_token(&key1.encoding_key, None, &claims);

    let result: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("kid-less token should fall back to the first JWKS key by default");
    assert_eq!(result.sub, "user-1");
}

/// Issue #341: a stock Keycloak realm publishes an RSA *encryption* key next to
/// its RSA signing key, identical in `kty`. With no `kid` on the token the
/// fallback used to take `keys.first()` — whichever JWKS member order happened
/// to put first — so a good token could be rejected with a bare
/// `InvalidSignature`. Key selection must skip the encryption key and find the
/// signing key behind it.
#[tokio::test]
async fn missing_kid_skips_an_encryption_key_to_reach_the_signing_key() {
    let enc = generate_rsa_key_for_use(Some("enc-key"), "enc");
    let sig = generate_rsa_key_for_use(Some("sig-key"), "sig");
    // Encryption key first, which is the ordering that used to break.
    let server = start_jwks_server(vec![enc.jwk.clone(), sig.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&sig.encoding_key, None, &claims);

    let validated: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("the encryption key must be skipped in favour of the signing key");
    assert_eq!(validated.sub, "user-1");
}

/// A `kid` naming an encryption key is not a licence to verify with it: the
/// filter applies to the `kid` branch too, so the key is passed over and the
/// lookup fails closed.
#[tokio::test]
async fn a_kid_naming_an_encryption_key_is_refused() {
    let enc = generate_rsa_key_for_use(Some("enc-key"), "enc");
    let server = start_jwks_server(vec![enc.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    // Genuinely signed by that key's private half — only its declared *use*
    // makes it unacceptable.
    let token = sign_token(&enc.encoding_key, Some("enc-key"), &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("an encryption key must never verify a signature");
    assert!(
        matches!(err, ValidationError::KeyNotFound),
        "expected the key to be passed over, got: {err}"
    );
}

/// `key_ops` is honoured on the same footing as `use` (RFC 7517 §4.3): a key
/// whose declared operations do not include `verify` is not a verification key.
#[tokio::test]
async fn a_key_whose_key_ops_exclude_verify_is_refused() {
    let mut key = generate_rsa_key(Some("kid-1"));
    key.jwk.key_ops = Some(vec!["encrypt".to_string()]);
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("a key that may not verify must not be selected");
    assert!(
        matches!(err, ValidationError::KeyNotFound),
        "expected the key to be passed over, got: {err}"
    );
}

/// The overwhelmingly common JWKS shape declares neither `use` nor `key_ops`.
/// Those keys must stay usable, or the filter would fail closed on almost
/// every IdP in existence.
#[tokio::test]
async fn a_key_declaring_neither_use_nor_key_ops_is_still_usable() {
    let key = generate_rsa_key(Some("kid-1"));
    assert!(key.jwk.r#use.is_none() && key.jwk.key_ops.is_none());
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let validated: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("a key declaring no use restriction must remain usable");
    assert_eq!(validated.sub, "user-1");
}

#[tokio::test]
async fn missing_kid_is_rejected_when_require_kid_is_enabled() {
    let key1 = generate_rsa_key(Some("k1"));
    let key2 = generate_rsa_key(Some("k2"));
    let server = start_jwks_server(vec![key1.jwk.clone(), key2.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600)).require_kid(true);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key1.encoding_key, None, &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("kid-less token must be rejected when require_kid is enabled");
    assert!(matches!(err, ValidationError::MissingKid));
}

#[tokio::test]
async fn require_kid_still_allows_tokens_that_present_a_kid() {
    let key1 = generate_rsa_key(Some("k1"));
    let key2 = generate_rsa_key(Some("k2"));
    let server = start_jwks_server(vec![key1.jwk.clone(), key2.jwk.clone()]).await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600)).require_kid(true);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-2".to_string(),
        exp: future_exp(),
        aud: None,
    };
    // Signed by the SECOND key and explicitly identifies it via `kid`.
    let token = sign_token(&key2.encoding_key, Some("k2"), &claims);

    let result: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("token presenting a kid should validate normally under require_kid");
    assert_eq!(result.sub, "user-2");
}

#[tokio::test]
async fn strategy_surfaces_strict_kid_rejection_as_an_error_not_a_silent_none() {
    let key1 = generate_rsa_key(Some("k1"));
    let server = start_jwks_server(vec![key1.jwk.clone()]).await;

    let validation_config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_kid(true)
        .build();

    let strategy: JwtStrategy<TestClaims> = JwtStrategy::new(validation_config);

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key1.encoding_key, None, &claims);

    let request = Request::builder()
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();

    let result = strategy.authenticate(&parts).await;
    assert!(
        result.is_err(),
        "a strict-kid rejection must surface as Err(AuthError), not be swallowed as Ok(None)"
    );
}

// --- RFC 8705 certificate-bound (`cnf.x5t#S256`) access token tests -------
//
// Covers issue #224: a `client_credentials` token stamped with
// `cnf.x5t#S256` (see `authkestra-op`'s `handle_client_credentials` tests
// for the OP-side stamping half) must be rejected by
// `JwtStrategy::require_cert_binding` unless the *same* certificate — by
// SHA-256 thumbprint — is presented on the connection used to redeem it.

/// Claims shape carrying an optional RFC 8705 `cnf` confirmation claim,
/// separate from `TestClaims` above so the existing tests in this file stay
/// untouched.
#[derive(Debug, Serialize, Deserialize)]
struct CertBoundClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<serde_json::Value>,
}

/// Builds an `http::request::Parts` carrying a `Bearer` token and,
/// optionally, a `ClientCertificateDer` request extension — standing in for
/// whatever a host application's mTLS-terminating layer would have inserted
/// (see `ClientCertificateDer`'s doc comment).
fn bearer_request_parts(token: &str, cert_der: Option<&[u8]>) -> http::request::Parts {
    let mut request = Request::builder()
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap();
    if let Some(cert_der) = cert_der {
        request
            .extensions_mut()
            .insert(ClientCertificateDer(cert_der.to_vec()));
    }
    let (parts, _) = request.into_parts();
    parts
}

#[tokio::test]
async fn cert_binding_accepts_token_when_presented_certificate_matches() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let cert_der = b"a fake DER-encoded client certificate for testing";
    let thumbprint = x5t_s256_thumbprint(cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_cert_binding(true)
        .build();
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = bearer_request_parts(&token, Some(cert_der));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    let identity = result.expect(
        "a certificate-bound token, redeemed with the same certificate it was bound to, must be accepted",
    );
    assert_eq!(identity.sub, "service-a");
}

#[tokio::test]
async fn cert_binding_rejects_token_when_presented_certificate_is_mismatched() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let bound_cert_der = b"the certificate the token was actually bound to";
    let presented_cert_der = b"a different, attacker-controlled certificate";
    let thumbprint = x5t_s256_thumbprint(bound_cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_cert_binding(true)
        .build();
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = bearer_request_parts(&token, Some(presented_cert_der));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a certificate-bound token presented with the WRONG certificate must be rejected"
    );
}

#[tokio::test]
async fn cert_binding_rejects_token_when_no_certificate_is_presented() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let bound_cert_der = b"the certificate the token was actually bound to";
    let thumbprint = x5t_s256_thumbprint(bound_cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_cert_binding(true)
        .build();
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    // No `ClientCertificateDer` extension at all — e.g. a stolen bearer
    // token replayed from a peer with no client certificate, or one that
    // is mTLS-authenticated but under a different certificate than the
    // token was bound to.
    let parts = bearer_request_parts(&token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a certificate-bound token presented with NO certificate at all must be rejected, \
         exactly like a mismatched one — mTLS alone does not restore proof-of-possession"
    );
}

#[tokio::test]
async fn cert_binding_is_not_enforced_when_require_cert_binding_is_false() {
    // Backward compatibility: a certificate-bound token is still accepted
    // as a plain bearer token when the resource server has not opted into
    // `require_cert_binding`.
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let bound_cert_der = b"the certificate the token was actually bound to";
    let thumbprint = x5t_s256_thumbprint(bound_cert_der);

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    assert!(!config.require_cert_binding);
    let strategy: JwtStrategy<CertBoundClaims> = JwtStrategy::new(config);

    let claims = CertBoundClaims {
        sub: "service-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "x5t#S256": thumbprint })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = bearer_request_parts(&token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error")
        .expect(
            "without require_cert_binding, a certificate-bound token is still a valid bearer token",
        );
    assert_eq!(result.sub, "service-a");
}

// --- Multi-issuer JWKS resolution (issue #243) ---------------------------
//
// A single resource verifier trusting several issuers at once. The security
// property under test is that the token's `iss` selects *which* JWKS verifies
// it, with no default arm: an `iss` outside the trust map is rejected rather
// than falling through to some other issuer's keys.

const ISS_A: &str = "https://issuer-a.example";
const ISS_B: &str = "https://issuer-b.example";
const ISS_UNTRUSTED: &str = "https://issuer-c.example";

/// Claims carrying an `iss`, kept separate from `TestClaims` so the
/// single-issuer tests above stay exactly as they were.
#[derive(Debug, Serialize, Deserialize)]
struct IssuedClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    sub: String,
    exp: usize,
}

fn issued_claims(iss: Option<&str>, sub: &str) -> IssuedClaims {
    IssuedClaims {
        iss: iss.map(|s| s.to_string()),
        sub: sub.to_string(),
        exp: future_exp(),
    }
}

fn cache_for(server: &MockServer) -> Arc<JwksCache> {
    Arc::new(JwksCache::new(jwks_url(server), Duration::from_secs(3600)))
}

/// A `Validation` matching what `JwtStrategy` derives for a trust map, for the
/// tests that exercise `validate_jwt_with_resolver` directly.
fn multi_issuer_validation(accepted: &[&str]) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(accepted);
    validation.required_spec_claims.insert("iss".to_string());
    validation.validate_aud = false;
    validation
}

#[tokio::test]
async fn multi_issuer_verifies_each_token_against_its_own_issuers_jwks() {
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .trusted_issuer(ISS_A, jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    assert_eq!(config.trusted_issuers.len(), 2);
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    for (iss, key, kid) in [
        (ISS_A, &key_a, "a-key"),
        // The point of the test: issuer B's token is verified with keys fetched
        // from B's endpoint, which A's JWKS does not contain.
        (ISS_B, &key_b, "b-key"),
    ] {
        let token = sign_token(
            &key.encoding_key,
            Some(kid),
            &issued_claims(Some(iss), "user-1"),
        );
        let identity = strategy
            .authenticate(&bearer_request_parts(&token, None))
            .await
            .unwrap_or_else(|e| panic!("authenticate should not error for {iss}: {e}"))
            .unwrap_or_else(|| panic!("a valid token from trusted issuer {iss} must be accepted"));
        assert_eq!(identity.iss.as_deref(), Some(iss));
    }
}

#[tokio::test]
async fn multi_issuer_rejects_a_token_whose_issuer_is_not_in_the_trust_map() {
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    // Signed by a key that IS published on a trusted endpoint, so the only
    // reason to reject is the issuer name itself.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_UNTRUSTED), "user-1"),
    );

    let trust_map = IssuerTrustMap::new()
        .with_issuer(ISS_A, cache_for(&server_a))
        .with_issuer(ISS_B, cache_for(&server_b));

    // Rejected *for being untrusted*, not incidentally by signature or audience.
    let err = validate_jwt_with_resolver::<IssuedClaims>(
        &token,
        &trust_map,
        &multi_issuer_validation(&[ISS_A, ISS_B]),
    )
    .await
    .expect_err("a token from an issuer outside the trust map must be rejected");
    assert!(
        matches!(&err, ValidationError::UntrustedIssuer(iss) if iss == ISS_UNTRUSTED),
        "expected UntrustedIssuer({ISS_UNTRUSTED}), got {err:?}"
    );

    // And the same through the strategy, which must not silently accept it.
    let config = ValidationConfig::builder()
        .trusted_issuer(ISS_A, jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);
    let res = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate must not fail on untrusted issuer");
    assert!(
        res.is_none(),
        "an untrusted issuer must be rejected gracefully as Ok(None) to allow fallback"
    );
}

#[tokio::test]
async fn multi_issuer_never_falls_back_to_the_single_issuer_jwks_url() {
    // `jwks_url` is set but no `issuer` names it, so it cannot be folded into
    // the trust map. It must NOT become a default arm for unknown issuers.
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    // Signed by the key published at the dangling `jwks_url`, claiming an
    // issuer nobody trusts. If `jwks_url` were used as a fallback this would
    // verify — that is precisely the issuer-confusion vulnerability.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_UNTRUSTED), "user-1"),
    );
    let res = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate must not fail on unnamed jwks_url");
    assert!(
        res.is_none(),
        "an unnamed jwks_url must never verify a token from an untrusted issuer"
    );

    // The trust map itself still works.
    let token = sign_token(
        &key_b.encoding_key,
        Some("b-key"),
        &issued_claims(Some(ISS_B), "user-1"),
    );
    assert!(strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate should not error")
        .is_some());
}

#[tokio::test]
async fn multi_issuer_rejects_a_token_claiming_issuer_a_but_signed_with_issuer_bs_key() {
    // Both issuers publish a key under the SAME `kid`, so `kid` lookup cannot be
    // what saves us: the resolver has to pick A's JWKS from `iss`, and the
    // signature then has to fail against A's key.
    let key_a = generate_rsa_key(Some("shared-kid"));
    let key_b = generate_rsa_key(Some("shared-kid"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let token = sign_token(
        &key_b.encoding_key,
        Some("shared-kid"),
        &issued_claims(Some(ISS_A), "attacker"),
    );

    let trust_map = IssuerTrustMap::new()
        .with_issuer(ISS_A, cache_for(&server_a))
        .with_issuer(ISS_B, cache_for(&server_b));

    let err = validate_jwt_with_resolver::<IssuedClaims>(
        &token,
        &trust_map,
        &multi_issuer_validation(&[ISS_A, ISS_B]),
    )
    .await
    .expect_err("a token claiming issuer A but signed with B's key must be rejected");
    match err {
        ValidationError::Jwt(e) => assert!(
            matches!(e.kind(), ErrorKind::InvalidSignature),
            "expected an invalid-signature rejection, got {:?}",
            e.kind()
        ),
        other => panic!("expected a signature failure against issuer A's key, got {other:?}"),
    }

    // Same token, same trust map, through the strategy: no identity.
    let config = ValidationConfig::builder()
        .trusted_issuer(ISS_A, jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);
    assert!(
        strategy
            .authenticate(&bearer_request_parts(&token, None))
            .await
            .expect("authenticate should not error")
            .is_none(),
        "cross-issuer key confusion must never yield an identity"
    );
}

#[tokio::test]
async fn multi_issuer_rejects_a_token_with_no_issuer_claim() {
    let key_a = generate_rsa_key(Some("a-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;

    // No `iss` at all: nothing names a key, and there is no default.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(None, "user-1"),
    );

    let trust_map = IssuerTrustMap::new().with_issuer(ISS_A, cache_for(&server_a));
    let err = validate_jwt_with_resolver::<IssuedClaims>(
        &token,
        &trust_map,
        &multi_issuer_validation(&[ISS_A]),
    )
    .await
    .expect_err("a token with no iss must be rejected in multi-issuer mode");
    assert!(
        matches!(err, ValidationError::MissingIssuer),
        "expected MissingIssuer, got {err:?}"
    );
}

#[tokio::test]
async fn the_single_issuer_pair_is_folded_into_the_trust_map_as_one_more_entry() {
    let key_a = generate_rsa_key(Some("a-key"));
    let key_b = generate_rsa_key(Some("b-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;
    let server_b = start_jwks_server(vec![key_b.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .issuer(ISS_A)
        .jwks_url(jwks_url(&server_a))
        .trusted_issuer(ISS_B, jwks_url(&server_b))
        .build();
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    for (iss, key, kid) in [(ISS_A, &key_a, "a-key"), (ISS_B, &key_b, "b-key")] {
        let token = sign_token(
            &key.encoding_key,
            Some(kid),
            &issued_claims(Some(iss), "user-1"),
        );
        assert!(
            strategy
                .authenticate(&bearer_request_parts(&token, None))
                .await
                .unwrap_or_else(|e| panic!("authenticate should not error for {iss}: {e}"))
                .is_some(),
            "the issuer/jwks_url pair must keep working alongside a trust map"
        );
    }
}

#[tokio::test]
async fn single_issuer_configuration_is_unchanged_by_multi_issuer_support() {
    // Regression guard: with no trust map this is exactly the pre-#243
    // verifier — one JWKS, one accepted issuer.
    let key_a = generate_rsa_key(Some("a-key"));
    let server_a = start_jwks_server(vec![key_a.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .issuer(ISS_A)
        .jwks_url(jwks_url(&server_a))
        .build();
    assert!(
        config.trusted_issuers.is_empty(),
        "no trust map may be configured unless the caller asked for one"
    );
    let strategy: JwtStrategy<IssuedClaims> = JwtStrategy::new(config);

    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_A), "user-1"),
    );
    let identity = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate should not error")
        .expect("a token from the configured issuer must still be accepted");
    assert_eq!(identity.sub, "user-1");

    // A different `iss`, signed by the very key this config trusts, is still
    // rejected by `Validation` — and still as `Ok(None)`, not an error, exactly
    // as before.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(Some(ISS_UNTRUSTED), "user-1"),
    );
    assert!(
        strategy
            .authenticate(&bearer_request_parts(&token, None))
            .await
            .expect("authenticate should not error")
            .is_none(),
        "a mismatched iss must still be rejected in single-issuer mode"
    );

    // Pre-existing `jsonwebtoken` semantics, unchanged here and pinned so that
    // changing it later is a deliberate act: `iss` is only checked when the
    // claim is present, so a token omitting it entirely is still accepted in
    // single-issuer mode. Multi-issuer mode does NOT inherit this (see
    // `multi_issuer_rejects_a_token_with_no_issuer_claim`), because there `iss`
    // is added to `required_spec_claims`.
    let token = sign_token(
        &key_a.encoding_key,
        Some("a-key"),
        &issued_claims(None, "user-1"),
    );
    let res = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await
        .expect("authenticate must not error on missing issuer");
    assert!(
        res.is_none(),
        "single-issuer mode now strictly requires the iss claim, failing as Ok(None)"
    );
}

/// A `with_resolver` strategy must still reject a token with no `iss`, even
/// when no static trust map is configured.
///
/// Raised in review of #254. `build_validation` inferred "multi-issuer" from
/// `trusted_issuers` being non-empty, but a `with_resolver` caller resolves
/// issuers dynamically and so configures no map at all — leaving that path with
/// neither `set_issuer` nor `iss` in `required_spec_claims`. Both backstops were
/// off precisely where the docs said they applied, so a resolver lax about
/// `None` would authenticate an issuer-less token.
///
/// The resolver here is deliberately maximally lax: it hands back the same
/// cache whatever the issuer, including `None`. The rejection must therefore
/// come from `Validation`, not from the resolver.
#[tokio::test]
async fn with_resolver_rejects_an_issuerless_token_even_with_no_trust_map() {
    struct AlwaysSame(Arc<JwksCache>);

    #[async_trait::async_trait]
    impl authkestra_resource::jwt::JwksResolver for AlwaysSame {
        async fn resolve(&self, _issuer: Option<&str>) -> Result<Arc<JwksCache>, ValidationError> {
            Ok(self.0.clone())
        }
    }

    let key = generate_rsa_key(Some("a-key"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    // No `iss` at all, signed by a key the resolver will happily hand over.
    let token = sign_token(&key.encoding_key, Some("a-key"), &issued_claims(None, "u"));

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    let strategy: JwtStrategy<IssuedClaims> =
        JwtStrategy::with_resolver(config, Box::new(AlwaysSame(cache_for(&server))));

    let result = strategy
        .authenticate(&bearer_request_parts(&token, None))
        .await;
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|id| id.is_none()),
        "an iss-less token must not authenticate through a custom resolver, got: {result:?}"
    );
}

/// Pins every documented default of a minimally-configured `ValidationConfig`.
///
/// The security-relevant assertions are `require_cert_binding` and
/// `require_kid`: both are documented as off by default, and flipping either
/// on would silently start *rejecting* tokens that a deployed resource server
/// accepts today — a change that no existing test would otherwise catch,
/// because every other test in this file opts in explicitly. See issue #247.
#[test]
fn builder_defaults_match_documented_behaviour() {
    let config = ValidationConfig::builder()
        .jwks_url("https://issuer.example.com/.well-known/jwks.json")
        .build();

    assert_eq!(
        config.jwks_url,
        "https://issuer.example.com/.well-known/jwks.json"
    );
    assert_eq!(config.refresh_interval, Duration::from_secs(3600));
    assert_eq!(config.issuer, None);
    assert!(config.audience.is_empty());
    assert_eq!(config.algorithms, vec![Algorithm::RS256]);
    assert!(
        !config.require_kid,
        "require_kid must stay off by default: turning it on would reject every token whose \
         header omits `kid`, which validated fine before"
    );
    assert!(
        !config.require_cert_binding,
        "require_cert_binding must stay off by default: turning it on would reject every \
         certificate-bound token not presented over a matching mTLS connection"
    );
    assert!(
        !config.require_dpop,
        "require_dpop must stay off by default: turning it on would reject every DPoP-bound \
         token not presented over the DPoP auth-scheme with a matching proof"
    );
}

// --- RFC 9449 DPoP key-bound (`cnf.jkt`) access token tests — authkestra#274
// Phase C -------------------------------------------------------------------
//
// Covers the same shape of gap #224/cert-binding closed for RFC 8705: a
// token stamped with `cnf.jkt` (see `authkestra-op`'s DPoP `/token` wiring)
// must be rejected by `JwtStrategy::require_dpop` unless the request
// presents a fresh, valid DPoP proof for that same key, bound to this
// specific access token — and, per RFC 9449 §7.1, presented via the `DPoP`
// auth-scheme, never `Bearer`.

/// Claims shape carrying an optional `cnf` confirmation claim, separate from
/// `CertBoundClaims` so a claims payload can be reused verbatim across both
/// binding checks if a future test wants both at once.
#[derive(Debug, Serialize, Deserialize)]
struct DpopBoundClaims {
    sub: String,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<serde_json::Value>,
}

fn dpop_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn dpop_b64_json(v: &serde_json::Value) -> String {
    dpop_b64(serde_json::to_vec(v).unwrap().as_slice())
}

/// Builds a real, genuinely Ed25519-signed DPoP proof. Mirrors the
/// (private, so unreachable from this integration-test binary)
/// `DpopProofBuilder` in `authkestra_resource::jwt`'s own unit tests, and
/// `authkestra_engine::token::dpop`'s before that.
struct DpopProofBuilder {
    signing_key: ed25519_dalek::SigningKey,
    htm: String,
    htu: String,
    jti: String,
    ath: Option<String>,
}

impl DpopProofBuilder {
    fn with_key_seed(seed: u8, htm: &str, jti: &str) -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            htm: htm.to_string(),
            htu: "https://resource.example.com/protected".to_string(),
            jti: jti.to_string(),
            ath: None,
        }
    }

    fn with_ath(mut self, ath: &str) -> Self {
        self.ath = Some(ath.to_string());
        self
    }

    fn with_htu(mut self, htu: &str) -> Self {
        self.htu = htu.to_string();
        self
    }

    fn jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": dpop_b64(self.signing_key.verifying_key().as_bytes()),
        })
    }

    fn expected_jkt(&self) -> String {
        authkestra_engine::token::dpop::compute_jwk_thumbprint(
            &serde_json::from_value(self.jwk()).unwrap(),
        )
        .unwrap()
    }

    fn build(&self) -> String {
        use ed25519_dalek::Signer;
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "EdDSA",
            "jwk": self.jwk(),
        });
        let mut payload = serde_json::json!({
            "htm": self.htm,
            "htu": self.htu,
            "iat": chrono::Utc::now().timestamp(),
            "jti": self.jti,
        });
        if let Some(ath) = &self.ath {
            payload["ath"] = serde_json::Value::String(ath.clone());
        }
        let signing_input = format!("{}.{}", dpop_b64_json(&header), dpop_b64_json(&payload));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", dpop_b64(&signature.to_bytes()))
    }
}

/// Builds `http::request::Parts` presenting `token` via the given
/// auth-scheme, with `dpop_proof`, if any, as the `DPoP` header.
fn scheme_request_parts(
    scheme: &str,
    token: &str,
    dpop_proof: Option<&str>,
) -> http::request::Parts {
    scheme_request_parts_with_uri(scheme, token, dpop_proof, "/")
}

/// As [`scheme_request_parts`], but lets the caller set the request's own
/// path — needed to exercise `ValidationConfig::dpop_resource_origin`,
/// which reconstructs the expected `htu` from this path.
fn scheme_request_parts_with_uri(
    scheme: &str,
    token: &str,
    dpop_proof: Option<&str>,
    uri: &str,
) -> http::request::Parts {
    let mut builder = Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, format!("{scheme} {token}"));
    if let Some(proof) = dpop_proof {
        builder = builder.header("DPoP", proof);
    }
    let request = builder.body(()).unwrap();
    let (parts, _) = request.into_parts();
    parts
}

#[tokio::test]
async fn dpop_accepts_a_valid_proof_presented_via_the_dpop_scheme() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config).with_dpop_replay_store(
        Arc::new(authkestra_engine::store::memory::MemoryStore::<
            authkestra_resource::dpop::DpopJtiRecord,
        >::new()),
    );

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-1");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts("DPoP", &token, Some(&proof));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    let identity = result.expect(
        "a DPoP-bound token, presented via the DPoP scheme with a valid matching proof, must be accepted",
    );
    assert_eq!(identity.sub, "user-a");
}

/// The regression test for the exact gap this whole test module is about:
/// RFC 9449 §7.1 requires a DPoP-bound token be presented via the `DPoP`
/// scheme, never `Bearer` — and before this fix, `authenticate` only ever
/// looked for `Bearer`, so no request shaped the way a spec-compliant DPoP
/// client actually sends one could ever reach the DPoP check at all.
#[tokio::test]
async fn dpop_rejects_a_bound_token_presented_via_the_bearer_scheme() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config).with_dpop_replay_store(
        Arc::new(authkestra_engine::store::memory::MemoryStore::<
            authkestra_resource::dpop::DpopJtiRecord,
        >::new()),
    );

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-2");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    // A genuinely valid proof is attached too — the point of this test is
    // that the *scheme* alone must be enough to refuse it, independent of
    // whether a valid proof also happens to be present.
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts("Bearer", &token, Some(&proof));

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a DPoP-bound token presented via the Bearer scheme must be rejected, even with a \
         genuinely valid DPoP proof attached"
    );
}

#[tokio::test]
async fn dpop_is_not_enforced_when_require_dpop_is_false() {
    // Backward compatibility: a DPoP-bound token is still accepted as a
    // plain bearer token when the resource server has not opted into
    // `require_dpop` — mirrors `cert_binding_is_not_enforced_when_require_
    // cert_binding_is_false` above.
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();
    assert!(!config.require_dpop);
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config);

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-3");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = scheme_request_parts("Bearer", &token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error")
        .expect("without require_dpop, a DPoP-bound token is still a valid bearer token");
    assert_eq!(result.sub, "user-a");
}

/// The other regression this test module is about: a replay-store outage
/// (or, as here, the fail-closed `NoDpopReplayStore` default) must surface
/// as `Err(AuthError)`, never `Ok(None)`. `Ok(None)` means "this strategy
/// declined, try the next one" under `AuthPolicy::FirstSuccess` — treating
/// an infrastructure failure that way would let a `Guard` chain silently
/// authenticate the request via some other strategy with the DPoP check
/// skipped entirely, rather than surfacing the outage.
#[tokio::test]
async fn dpop_replay_store_outage_surfaces_as_err_not_ok_none() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    // Deliberately not wiring `with_dpop_replay_store` — this strategy's
    // replay store is the fail-closed `NoDpopReplayStore` default.
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config);

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-e2e-4");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts("DPoP", &token, Some(&proof));

    let result = strategy.authenticate(&parts).await;
    assert!(
        result.is_err(),
        "no replay store is configured; this must surface as Err(AuthError), not be swallowed \
         as Ok(None)"
    );
}

/// RFC 9449 §7.1's other direction: a request presented via the `DPoP`
/// scheme is a claim that the token is DPoP-bound. A token with no
/// `cnf.jkt` at all can't back that claim, so it must be refused too, not
/// silently treated the same as if it had arrived via `Bearer`.
#[tokio::test]
async fn dpop_rejects_dpop_scheme_presentation_of_an_unbound_token() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config);

    // No `cnf` claim at all — an ordinary, unbound token.
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: None,
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let parts = scheme_request_parts("DPoP", &token, None);

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a token with no cnf.jkt presented via the DPoP scheme must be refused, not silently \
         accepted as an ordinary bearer token"
    );
}

/// `ValidationConfig::dpop_resource_origin` opt-in: with it configured, a
/// proof minted for this exact URL (origin + request path) is accepted.
#[tokio::test]
async fn dpop_htu_check_accepts_when_configured_origin_matches() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .dpop_resource_origin("https://api.example.com")
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config).with_dpop_replay_store(
        Arc::new(authkestra_engine::store::memory::MemoryStore::<
            authkestra_resource::dpop::DpopJtiRecord,
        >::new()),
    );

    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-htu-1")
        .with_htu("https://api.example.com/widgets/42");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts_with_uri("DPoP", &token, Some(&proof), "/widgets/42");

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_some(),
        "a proof minted for this exact configured-origin URL must be accepted"
    );
}

/// The other half: with `dpop_resource_origin` configured, a proof minted
/// for a *different* URL — e.g. one forwarded from another resource server
/// within its freshness window — must be refused. This is exactly the
/// cross-service forwarding gap that leaving `dpop_resource_origin` unset
/// does not close.
#[tokio::test]
async fn dpop_htu_check_rejects_when_configured_origin_url_mismatches() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;

    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .require_dpop(true)
        .dpop_resource_origin("https://api.example.com")
        .build();
    let strategy: JwtStrategy<DpopBoundClaims> = JwtStrategy::new(config).with_dpop_replay_store(
        Arc::new(authkestra_engine::store::memory::MemoryStore::<
            authkestra_resource::dpop::DpopJtiRecord,
        >::new()),
    );

    // The proof was minted for a different resource server's URL entirely.
    let proof_builder = DpopProofBuilder::with_key_seed(11, "GET", "jti-htu-2")
        .with_htu("https://a-different-service.example.com/widgets/42");
    let claims = DpopBoundClaims {
        sub: "user-a".to_string(),
        exp: future_exp(),
        aud: None,
        cnf: Some(serde_json::json!({ "jkt": proof_builder.expected_jkt() })),
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let proof = proof_builder
        .with_ath(&x5t_s256_thumbprint(token.as_bytes()))
        .build();
    let parts = scheme_request_parts_with_uri("DPoP", &token, Some(&proof), "/widgets/42");

    let result = strategy
        .authenticate(&parts)
        .await
        .expect("authenticate should not error");
    assert!(
        result.is_none(),
        "a proof minted for a different resource server's URL must be refused once \
         dpop_resource_origin is configured"
    );
}

/// `JwksCache::with_client` must actually route the JWKS fetch through the supplied client.
///
/// The motivating shape is a resource server whose issuer publishes its JWKS inside the cluster
/// under a private CA: the default client trusts only the platform store, so the endpoint is
/// unreachable and the deployment is pushed toward dialling the public hostname (leaving and
/// re-entering the network to fetch keys) or toward `SSL_CERT_FILE`, which swaps the trust store
/// for every outbound connection in the process rather than this one fetch.
///
/// TLS itself is not what this asserts -- standing up a private CA and an HTTPS mock would test
/// rustls, not this crate. What must be proven is the seam: that the injected client, and not an
/// internally-constructed default, issues the request. A required header stands in for the
/// client-carried configuration, since it is observable at the mock without any TLS setup.
#[tokio::test]
async fn with_client_routes_the_jwks_fetch_through_the_supplied_client() {
    let key = generate_rsa_key(Some("client-injection"));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .and(header("x-authkestra-client", "injected"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&JwksBody {
            keys: vec![key.jwk.clone()],
        }))
        .mount(&server)
        .await;

    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-authkestra-client",
        http::HeaderValue::from_static("injected"),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("a client with a static default header always builds");

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(300)).with_client(client);

    let jwks = cache
        .get_jwks()
        .await
        .expect("the mock only answers a request carrying the injected client's header");
    assert_eq!(jwks.keys.len(), 1);
}

/// The control for the test above: without `with_client`, the default client sends no such header,
/// so the same mock does not match and the fetch fails. Without this, the test above would still
/// pass if `with_client` stored the client and `refresh` quietly ignored it -- the mock would be
/// unmatched either way only if the header were genuinely required, and this proves it is.
#[tokio::test]
async fn default_client_does_not_carry_the_injected_configuration() {
    let key = generate_rsa_key(Some("client-injection-control"));
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .and(header("x-authkestra-client", "injected"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&JwksBody {
            keys: vec![key.jwk.clone()],
        }))
        .mount(&server)
        .await;

    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(300));

    assert!(
        cache.get_jwks().await.is_err(),
        "the default client sends no injected header, so the mock must not match -- if this \
         passes, the header is not actually discriminating and the sibling test proves nothing"
    );
}

/// The twelve algorithms Keycloak advertises in
/// `id_token_signing_alg_values_supported`, in the order a realm returns them —
/// four key families in one list.
fn keycloak_signing_algs() -> Vec<Algorithm> {
    vec![
        Algorithm::PS384,
        Algorithm::RS384,
        Algorithm::EdDSA,
        Algorithm::ES384,
        Algorithm::HS256,
        Algorithm::HS512,
        Algorithm::ES256,
        Algorithm::RS256,
        Algorithm::HS384,
        Algorithm::PS256,
        Algorithm::PS512,
        Algorithm::RS512,
    ]
}

/// Issue #335: a validation policy naming more than one key family — which is
/// exactly what an OIDC discovery document yields — must still verify a token
/// signed with one of the algorithms it lists.
///
/// `jsonwebtoken` requires every entry of `Validation::algorithms` to match the
/// verifying key's family, not just the header's `alg`, so before the fix this
/// list rejected every token from every Keycloak deployment with a bare
/// `InvalidAlgorithm`.
#[tokio::test]
async fn multi_family_algorithm_policy_verifies_a_token_from_one_of_its_families() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(300));

    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = keycloak_signing_algs();
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let validated: TestClaims = validate_jwt_generic(&token, &cache, &validation)
        .await
        .expect("an RS256 token must verify against the RS256 key that signed it");
    assert_eq!(validated.sub, "user-1");
}

/// Narrowing the policy to the header's family must not turn it into "any
/// algorithm goes": an algorithm the caller never listed is still refused.
#[tokio::test]
async fn rejects_an_algorithm_the_policy_does_not_list() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(300));

    // A policy that accepts EC and Ed only — the token below is neither.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.algorithms = vec![Algorithm::ES256, Algorithm::ES384, Algorithm::EdDSA];
    validation.validate_aud = false;

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);

    let err = validate_jwt_generic::<TestClaims>(&token, &cache, &validation)
        .await
        .expect_err("RS256 is not in the policy and must be rejected");
    assert!(
        matches!(&err, ValidationError::InvalidToken(msg) if msg.contains("RS256")),
        "expected an unaccepted-algorithm rejection naming RS256, got: {err}"
    );
}

/// The classic algorithm-confusion attack: the attacker takes the *public* RSA
/// key from the JWKS, uses its bytes as an HMAC secret, and presents an
/// `HS256`-signed token. Keycloak's advertised list contains both `RS256` and
/// `HS256`, so narrowing to the header's family leaves `HS256` in the policy —
/// the attack must be stopped by the key's own family check instead, before the
/// public key ever reaches an HMAC verifier.
#[tokio::test]
async fn rejects_hmac_token_verified_against_an_rsa_jwks_key() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(300));

    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = keycloak_signing_algs();
    validation.validate_aud = false;

    // Sign with the published modulus as the shared secret — everything the
    // attacker needs is in the JWKS.
    let public_bytes = URL_SAFE_NO_PAD
        .decode(key.jwk.n.as_ref().expect("RSA JWK carries 'n'"))
        .expect("'n' is base64url");
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("kid-1".to_string());
    let forged = encode(
        &header,
        &TestClaims {
            sub: "attacker".to_string(),
            exp: future_exp(),
            aud: None,
        },
        &EncodingKey::from_secret(&public_bytes),
    )
    .expect("failed to forge token");

    let err = validate_jwt_generic::<TestClaims>(&forged, &cache, &validation)
        .await
        .expect_err("an HS256 token must never be verified with an RSA JWKS key");
    assert!(
        matches!(&err, ValidationError::Jwt(e) if matches!(e.kind(), ErrorKind::InvalidKeyFormat)),
        "expected the RSA key to be refused by the HMAC verifier, got: {err}"
    );
}

// --- Why a token was rejected (#353) ---
//
// `JwtStrategy::authenticate` declines an invalid token with `Ok(None)` so
// another strategy may still run. That decline used to be silent, which left
// the resource server unable to answer the question #335 was filed to ask:
// why was this token rejected? These assert the reason is now recorded, and
// that the credential itself still is not.

/// Routes each thread's `tracing` output to that thread's own buffer, and
/// discards it on threads that are not capturing.
///
/// A **global** subscriber, installed once, rather than a thread-local one.
/// `tracing` caches callsite interest globally and a thread-local subscriber
/// does not invalidate that cache, so any test reaching a callsite while no
/// subscriber is installed gets its interest cached as "never" — and a later
/// thread-local capture there sees nothing. Rebuilding the cache does not fix
/// it either, because the non-capturing tests run concurrently and re-cache
/// "never" immediately after. Both were tried; both produced a capture that
/// passed alone and failed in a parallel run (#353).
mod capture {
    use std::cell::RefCell;
    use std::io;
    use std::sync::{Arc, Mutex, Once};

    thread_local! {
        static SINK: RefCell<Option<Arc<Mutex<Vec<u8>>>>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Copy, Default)]
    pub struct ThreadSink;

    impl io::Write for ThreadSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            SINK.with(|sink| {
                if let Some(target) = sink.borrow().as_ref() {
                    target.lock().unwrap().extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadSink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            *self
        }
    }

    static INSTALL: Once = Once::new();

    fn install() {
        INSTALL.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_writer(ThreadSink)
                .with_max_level(tracing::Level::TRACE)
                .without_time()
                .try_init();
        });
    }

    /// Starts capturing on this thread; the returned handle yields the output.
    pub struct Handle(Arc<Mutex<Vec<u8>>>);

    impl Handle {
        pub fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            SINK.with(|sink| *sink.borrow_mut() = None);
        }
    }

    pub fn start() -> Handle {
        install();
        let buffer = Arc::new(Mutex::new(Vec::new()));
        SINK.with(|sink| *sink.borrow_mut() = Some(Arc::clone(&buffer)));
        Handle(buffer)
    }
}

/// Runs `strategy.authenticate` against a Bearer `token`, capturing logs.
async fn authenticate_capturing(
    config: ValidationConfig,
    token: &str,
) -> (
    Result<Option<TestClaims>, authkestra_engine::error::AuthError>,
    String,
) {
    let captured = capture::start();

    let strategy: JwtStrategy<TestClaims> = JwtStrategy::new(config);
    let request = Request::builder()
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(())
        .unwrap();
    let (parts, _) = request.into_parts();

    let result = strategy.authenticate(&parts).await;
    let logs = captured.contents();
    (result, logs)
}

/// An expired token is declined, and the reason is now on the record. This is
/// #335's question — "my token looks fine, why is it refused?" — answered at
/// the layer that refused it.
#[tokio::test(flavor = "current_thread")]
async fn a_token_that_fails_validation_records_why() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .leeway(0)
        .build();

    let token = expired_token(&key, 120);
    let (result, logs) = authenticate_capturing(config, &token).await;

    assert!(
        matches!(result, Ok(None)),
        "an invalid token is a decline, not a hard error"
    );
    assert!(
        logs.contains("token failed validation"),
        "the decline should be recorded; got:\n{logs}"
    );
    assert!(
        logs.contains("ExpiredSignature"),
        "and it should say which check failed; got:\n{logs}"
    );
    assert!(
        !logs.contains(&token),
        "the bearer token must never be logged:\n{logs}"
    );
}

/// An unreachable JWKS endpoint is not a bad credential — it is not knowing.
/// It surfaces as a hard error rather than a decline, and both the fetch
/// failure and that distinction are now visible.
#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_jwks_endpoint_is_reported_and_is_not_a_decline() {
    let key = generate_rsa_key(Some("kid-1"));
    // A port nothing is listening on.
    let config = ValidationConfig::builder()
        .jwks_url("http://127.0.0.1:1/.well-known/jwks.json")
        .build();

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&key.encoding_key, Some("kid-1"), &claims);
    let (result, logs) = authenticate_capturing(config, &token).await;

    assert!(
        result.is_err(),
        "not being able to reach the JWKS is 'we cannot tell', not 'the token is bad'"
    );
    assert!(
        logs.contains("could not reach the JWKS endpoint"),
        "the fetch failure should be reported at the point it happens; got:\n{logs}"
    );
    assert!(
        logs.contains("could not determine whether the token is valid"),
        "and distinguished from a validation failure; got:\n{logs}"
    );
}

/// A token naming a `kid` the issuer does not publish: the endpoint answered,
/// the key is simply not there. Reported distinctly from a fetch failure,
/// after the refresh-for-rotation retry.
#[tokio::test(flavor = "current_thread")]
async fn a_token_naming_an_unknown_kid_says_the_jwks_lacks_it() {
    let served = generate_rsa_key(Some("kid-served"));
    let other = generate_rsa_key(Some("kid-unknown"));
    let server = start_jwks_server(vec![served.jwk.clone()]).await;
    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    let token = sign_token(&other.encoding_key, Some("kid-unknown"), &claims);
    let (_result, logs) = authenticate_capturing(config, &token).await;

    assert!(
        logs.contains("refreshing in case of rotation"),
        "the rotation retry should be visible; got:\n{logs}"
    );
    assert!(
        logs.contains("does not contain"),
        "and the give-up should say the JWKS lacks the key; got:\n{logs}"
    );
}

/// Review finding on #358: with no `kid`, `find_key` falls back to the first
/// key, so the only way to reach the give-up branch is an empty key set — the
/// token named nothing. Reporting that as "token names a key the JWKS does not
/// contain" described a fault that had not happened.
#[tokio::test(flavor = "current_thread")]
async fn an_empty_jwks_does_not_claim_the_token_named_a_missing_key() {
    let key = generate_rsa_key(None);
    // The endpoint answers, with no keys at all.
    let server = start_jwks_server(vec![]).await;
    let config = ValidationConfig::builder()
        .jwks_url(jwks_url(&server))
        .build();

    let claims = TestClaims {
        sub: "user-1".to_string(),
        exp: future_exp(),
        aud: None,
    };
    // No `kid` on the token either, which is what selects the fallback path.
    let token = sign_token(&key.encoding_key, None, &claims);
    let (_result, logs) = authenticate_capturing(config, &token).await;

    assert!(
        logs.contains("no kid and the issuer's JWKS has no key"),
        "an empty key set should be reported as such; got:\n{logs}"
    );
    assert!(
        !logs.contains("token names a key"),
        "the token named no key, so it must not be blamed for one; got:\n{logs}"
    );
}

// --- #353: the validation path names why it refused -------------------------
//
// Every way `validate_jwt_generic` can fail arrived by `?` and emitted
// nothing, so a rejected token said only that it was rejected. There was also
// no span, so nothing tied the events of one validation together — which #353
// names as what makes this path expensive to debug, with #335's
// `InvalidAlgorithm` as the evidence.

/// A rejection now says what went wrong.
#[tokio::test]
async fn a_rejected_token_is_logged_with_its_reason() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let token = expired_token(&key, 5);

    let captured = capture::start();
    let result =
        validate_jwt_generic::<TestClaims>(&token, &cache, &validation_with_leeway(0)).await;
    let logs = captured.contents();

    assert!(result.is_err(), "precondition: zero leeway rejects this");
    assert!(logs.contains("token rejected"), "got:\n{logs}");
    assert!(
        logs.contains("ExpiredSignature"),
        "the reason must survive into the log; got:\n{logs}"
    );
}

/// The span carries the two fields anyone debugging this asks for first, and
/// carries them even when the validation then fails.
#[tokio::test]
async fn the_validation_span_records_kid_and_alg() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let token = expired_token(&key, 5);

    let captured = capture::start();
    let _ = validate_jwt_generic::<TestClaims>(&token, &cache, &validation_with_leeway(0)).await;
    let logs = captured.contents();

    assert!(logs.contains("validate_jwt"), "no span; got:\n{logs}");
    assert!(logs.contains("kid-1"), "kid not recorded; got:\n{logs}");
    assert!(logs.contains("RS256"), "alg not recorded; got:\n{logs}");
}

/// An accepted token is observable too — otherwise the logs only ever show
/// failures, and "did this request authenticate at all?" stays unanswerable.
#[tokio::test]
async fn an_accepted_token_is_logged() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let token = expired_token(&key, 30);

    let captured = capture::start();
    let result = validate_jwt_generic::<TestClaims>(
        &token,
        &cache,
        &validation_with_leeway(DEFAULT_LEEWAY_SECS),
    )
    .await;
    let logs = captured.contents();

    assert!(result.is_ok());
    assert!(logs.contains("token accepted"), "got:\n{logs}");
}

/// The token is the credential. A rejection that echoed it would put a live
/// bearer token into whatever collects the logs.
#[tokio::test]
async fn the_validation_path_never_logs_the_token() {
    let key = generate_rsa_key(Some("kid-1"));
    let server = start_jwks_server(vec![key.jwk.clone()]).await;
    let cache = JwksCache::new(jwks_url(&server), Duration::from_secs(3600));
    let token = expired_token(&key, 5);

    let captured = capture::start();
    let _ = validate_jwt_generic::<TestClaims>(&token, &cache, &validation_with_leeway(0)).await;
    let logs = captured.contents();

    assert!(
        !logs.contains(&token),
        "the token reached the logs:\n{logs}"
    );
}
