//! # Axum OIDC + DPoP + Step-Up Example
//!
//! Runnable standalone in-memory OpenID Provider and Resource Server demonstrating:
//! 1. RFC 9449 §8 DPoP Nonce challenge loop (`use_dpop_nonce`) on `/token`.
//! 2. Fresh `DPoP-Nonce` returned on successful HTTP 200 OK responses.
//! 3. Standard OIDC discovery (`/.well-known/openid-configuration`) and JWKS (`/jwks`, `/jwks.json`).
//! 4. Pre-seeded fixture client (`client_id: "test-client"`).
//! 5. Resource server endpoints wired with `authkestra::resource` (`JwtStrategy`,
//!    `ValidationConfig::static_jwks`, `dpop_resource_origin`, `DpopReplayStore`,
//!    `StepUpRequirement`) and `authkestra::axum::Auth<I>` enforcing DPoP binding
//!    and RFC 9470 step-up authentication (`acr: "2"`).
//!
//! ## Dual Execution Mode:
//! - Default / no args: executes automated end-to-end client verification against an in-process server
//!   (the only mode in which synthetic `/api/step-up` claim minting is enabled).
//! - `--serve` or `PORT=<port>`: binds to the specified port as a standing daemon and logs
//!   `READY: listening on http://...` for external testrunners (e.g. `fespalier` CI). In `--serve`
//!   mode, synthetic `/api/step-up` elevation is disabled (`403 step_up_verification_required`).

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use authkestra::axum::op::{axum_jwks_handler, OpExt};
use authkestra::axum::{Auth, AxumError};
use authkestra::core::auth::session::Session;
use authkestra::core::oauth2::client::{ClientRegistration, GrantType};
use authkestra::core::oauth2::code::AuthorizationCode;
use authkestra::core::oauth2::device::DeviceCodeSession;
use authkestra::core::oauth2::refresh::RefreshToken;
use authkestra::core::store::memory::MemoryStore;
use authkestra::core::store::KvStore;
use authkestra::core::token::dpop_nonce::DpopNonces;
use authkestra::core::{Identity, SessionConfig, SessionStore, TokenManager};
use authkestra::op::store::CompositeOpStore;
use authkestra::op::{CloneableOpStore, DpopJtiRecord, OpConfig};
use authkestra::resource::jwt::{Jwks, JwtStrategy, ValidationConfig};
use authkestra::resource::{
    DpopJtiRecord as ResourceDpopJtiRecord, DpopReplayStore, Guard, StepUpRequirement,
};
use axum::extract::{FromRef, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::pkcs8::EncodePrivateKey;
use sha2::{Digest, Sha256};

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Pre-seeded fixture OAuth client identifier (`client_id`) accepted by the example OP
/// and required as the target audience (`aud`) by [`AppState::client_guard`] and
/// [`AppState::stepup_guard`].
pub const CLIENT_ID: &str = "test-client";

/// JWT claims verified for low-assurance DPoP-bound resource access (`/api/step-up`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ActionClaims {
    /// Subject identifier authenticated by the issuer.
    pub sub: String,
    /// Optional Authentication Context Class Reference (`acr`) asserted by the token.
    #[serde(default)]
    pub acr: Option<String>,
    /// Optional RFC 9449 confirmation (`cnf`) object carrying the DPoP key thumbprint.
    #[serde(default)]
    pub cnf: Option<CnfClaim>,
}

/// RFC 7800 / RFC 9449 confirmation (`cnf`) claim containing a JWK SHA-256 thumbprint (`jkt`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CnfClaim {
    /// Base64url-encoded SHA-256 JWK thumbprint bound to the client's DPoP proof key.
    pub jkt: String,
}

/// Distinct newtype so `/api/high-value-action` resolves its own [`Guard`]
/// configured with [`StepUpRequirement`] (`acr_values = "2"`), separate from
/// `/api/step-up`'s [`Guard<ActionClaims>`].
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(transparent)]
pub struct StepUpClaims(pub ActionClaims);

/// Shared Axum state for the standalone OP and DPoP-protected resource endpoints.
///
/// All stores (`op_store`, `session_store`, replay caches, and the generated RS256
/// signing key) live strictly in process memory for the lifetime of this state and are
/// reset on restart. Both guards require tokens issued by the configured `issuer` URL
/// with audience [`CLIENT_ID`] and DPoP proofs bound to that origin.
#[derive(Clone)]
pub struct AppState {
    /// Composite in-memory OpenID Provider store (clients, codes, refresh tokens, device codes, DPoP state).
    pub op_store: Arc<dyn CloneableOpStore>,
    /// Asymmetric RS256 token signer/verifier whose public key is published on `/jwks`.
    pub tokens: Arc<TokenManager>,
    /// In-memory interactive session store required by the OP router extractors.
    pub session_store: Arc<dyn SessionStore>,
    /// Session configuration for the OP router extractors.
    pub session_config: SessionConfig,
    /// OpenID Provider metadata configuration (`issuer`, grants, TTLs, scopes).
    pub config: OpConfig,
    /// Resource guard enforcing valid DPoP binding without a step-up `acr` requirement.
    pub client_guard: Arc<Guard<ActionClaims>>,
    /// Resource guard enforcing DPoP binding plus RFC 9470 `acr_values = "2"` step-up assurance.
    pub stepup_guard: Arc<Guard<StepUpClaims>>,
    /// Explicitly unsafe flag enabled only by the in-process self-test harness so
    /// `--serve` cannot mint elevated `acr = "2"` claims from a low-assurance token.
    allow_unsafe_synthetic_step_up: bool,
}

impl FromRef<AppState> for Result<Arc<dyn CloneableOpStore>, AxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.op_store.clone())
    }
}

impl FromRef<AppState> for Result<Arc<TokenManager>, AxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.tokens.clone())
    }
}

impl FromRef<AppState> for Result<Arc<dyn SessionStore>, AxumError> {
    fn from_ref(state: &AppState) -> Self {
        Ok(state.session_store.clone())
    }
}

impl FromRef<AppState> for SessionConfig {
    fn from_ref(state: &AppState) -> Self {
        state.session_config.clone()
    }
}

impl FromRef<AppState> for OpConfig {
    fn from_ref(state: &AppState) -> Self {
        state.config.clone()
    }
}

impl FromRef<AppState> for Arc<Guard<ActionClaims>> {
    fn from_ref(state: &AppState) -> Self {
        state.client_guard.clone()
    }
}

impl FromRef<AppState> for Arc<Guard<StepUpClaims>> {
    fn from_ref(state: &AppState) -> Self {
        state.stepup_guard.clone()
    }
}

/// Protected resource endpoint requiring DPoP binding (`htu`, `htm`, `ath`,
/// `jti` replay) and RFC 9470 step-up ACR level 2 via [`Auth<StepUpClaims>`].
async fn high_value_action_handler(Auth(StepUpClaims(claims)): Auth<StepUpClaims>) -> Response {
    tracing::info!(
        sub = %claims.sub,
        acr = claims.acr.as_deref().unwrap_or(""),
        "high-value step-up action authorized"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "action": "high-value-action",
            "sub": claims.sub,
            "acr": claims.acr.as_deref().unwrap_or("")
        })),
    )
        .into_response()
}

/// Self-test-only synthetic step-up endpoint exchanging a DPoP-bound token (verified via
/// [`Auth<ActionClaims>`]) for an elevated ACR level 2 token bound to the same `cnf.jkt`.
///
/// Always rejects requests unless constructed through the internal self-test mode
/// (`allow_unsafe_synthetic_step_up`), preventing low-assurance tokens from elevating in `--serve`.
async fn step_up_handler(
    State(state): State<AppState>,
    Auth(claims): Auth<ActionClaims>,
) -> Response {
    tracing::debug!(
        sub = %claims.sub,
        has_cnf = claims.cnf.is_some(),
        "evaluating step-up token exchange request"
    );

    if !state.allow_unsafe_synthetic_step_up {
        tracing::warn!(
            sub = %claims.sub,
            "step-up exchange rejected: synthetic claim minting disabled outside self-test mode"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "step_up_verification_required",
                "error_description": "Synthetic step-up elevation is disabled in server mode; verify an interactive re-authentication event before minting acr=2 claims."
            })),
        )
            .into_response();
    }

    let Some(cnf) = claims.cnf else {
        tracing::warn!(
            sub = %claims.sub,
            "step-up exchange rejected: access token missing cnf DPoP key binding"
        );
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "DPoP error=\"invalid_token\"")],
            Json(serde_json::json!({
                "error": "invalid_token",
                "error_description": "Token not DPoP-bound"
            })),
        )
            .into_response();
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => {
            tracing::error!(error = %e, "system clock precedes UNIX_EPOCH during step-up");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "System clock error"
                })),
            )
                .into_response();
        }
    };

    // Issue synthetic elevated token (self-test mode only) with acr: "2", auth_time, and same cnf.jkt binding
    let mut extra = HashMap::new();
    extra.insert("acr".to_string(), serde_json::json!("2"));
    extra.insert("auth_time".to_string(), serde_json::json!(now));
    extra.insert("cnf".to_string(), serde_json::json!({ "jkt": cnf.jkt }));
    extra.insert("amr".to_string(), serde_json::json!(["pwd", "mfa"]));

    let identity = Identity {
        provider_id: "op".to_string(),
        external_id: claims.sub.clone(),
        username: Some(claims.sub.clone()),
        email: None,
        attributes: HashMap::new(),
    };

    let elevated_token = match state.tokens.issue_user_token_with_extra(
        identity,
        3600,
        Some("openid profile api step_up".to_string()),
        Some(CLIENT_ID.to_string()),
        extra,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(
                sub = %claims.sub,
                error = %e,
                "failed to sign elevated step-up token"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": e.to_string()
                })),
            )
                .into_response();
        }
    };

    tracing::info!(
        sub = %claims.sub,
        acr = "2",
        "issued synthetic step-up token in isolated self-test mode"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": elevated_token,
            "token_type": "DPoP",
            "expires_in": 3600,
            "acr": "2"
        })),
    )
        .into_response()
}

/// Builds the OpenID Provider and DPoP-protected Axum router for `--serve` and library callers.
///
/// The configured `issuer` URL is baked into discovery metadata, minted tokens' `iss` claim,
/// and DPoP `htu` validation (`dpop_resource_origin`). All stores live solely in memory for
/// the lifetime of the returned [`AppState`], and synthetic `/api/step-up` elevation is
/// disabled by default (`403 step_up_verification_required`).
pub async fn build_app(issuer: String) -> AppResult<(Router, AppState)> {
    build_app_with_mode(issuer, false).await
}

async fn build_app_with_mode(
    issuer: String,
    allow_unsafe_synthetic_step_up: bool,
) -> AppResult<(Router, AppState)> {
    let clients = MemoryStore::<ClientRegistration>::new();
    #[allow(deprecated)]
    clients
        .set(
            CLIENT_ID,
            ClientRegistration {
                client_id: CLIENT_ID.to_string(),
                client_secret_hash: None,
                redirect_uris: vec!["http://localhost:3000/callback".to_string()],
                grant_types: vec![
                    GrantType::AuthorizationCode,
                    GrantType::ClientCredentials,
                    GrantType::RefreshToken,
                ],
                scopes: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "api".to_string(),
                    "step_up".to_string(),
                ],
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            Duration::from_secs(86400),
        )
        .await?;

    let store = CompositeOpStore::new(
        clients,
        MemoryStore::<AuthorizationCode>::new(),
        MemoryStore::<RefreshToken>::new(),
        MemoryStore::<DeviceCodeSession>::new(),
    )
    .with_dpop_replay_store(MemoryStore::<DpopJtiRecord>::new())
    .with_dpop_nonces(DpopNonces::random(Duration::from_secs(300)));

    let op_store: Arc<dyn CloneableOpStore> = Arc::new(store);

    let rsa_pem = generate_rsa_pem()?;
    let tokens = Arc::new(TokenManager::new_asymmetric(
        &rsa_pem,
        Some(issuer.clone()),
        Some("op-key-1".to_string()),
    )?);
    let session_store: Arc<dyn SessionStore> = Arc::new(MemoryStore::<Session>::new());
    let session_config = SessionConfig::default();

    let config = OpConfig {
        issuer: issuer.clone(),
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "api".to_string(),
            "step_up".to_string(),
        ],
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "client_credentials".to_string(),
            "refresh_token".to_string(),
        ],
        id_token_signing_alg: "RS256".to_string(),
        authorization_code_ttl_secs: 600,
        access_token_ttl_secs: 3600,
        device_code_ttl_secs: 600,
        token_exchange_enabled: false,
    };

    let op_jwk = tokens
        .public_jwk()
        .ok_or("asymmetric TokenManager must expose a public JWK")?;
    let jwks = Jwks::from_keys(vec![op_jwk]);
    let make_validation_config = || {
        ValidationConfig::builder()
            .static_jwks(jwks.clone())
            .issuer(&issuer)
            .audience(CLIENT_ID)
            .require_dpop(true)
            .dpop_resource_origin(&issuer)
            .build()
    };

    // Shared resource-server DPoP replay store across resource endpoints so a
    // captured proof cannot be replayed across requests or endpoints.
    let resource_replay_store: Arc<dyn DpopReplayStore> =
        Arc::new(MemoryStore::<ResourceDpopJtiRecord>::new());

    let client_guard = Arc::new(
        Guard::builder()
            .strategy(
                JwtStrategy::<ActionClaims>::new(make_validation_config())
                    .with_dpop_replay_store(resource_replay_store.clone()),
            )
            .build(),
    );
    let stepup_guard = Arc::new(
        Guard::builder()
            .strategy(
                JwtStrategy::<StepUpClaims>::new(make_validation_config())
                    .with_dpop_replay_store(resource_replay_store)
                    .with_step_up(StepUpRequirement::new().with_acr_values("2")),
            )
            .build(),
    );

    let state = AppState {
        op_store,
        tokens,
        session_store,
        session_config,
        config,
        client_guard,
        stepup_guard,
        allow_unsafe_synthetic_step_up,
    };

    let app = Router::new()
        .merge(state.op_axum_router())
        .route("/jwks", get(axum_jwks_handler::<AppState>))
        .route("/api/step-up", post(step_up_handler))
        .route("/api/high-value-action", get(high_value_action_handler))
        .with_state(state.clone());

    Ok((app, state))
}

#[tokio::main]
async fn main() -> AppResult<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let args: Vec<String> = std::env::args().collect();
    let serve_flag = args.iter().any(|a| a == "--serve");
    let port_var = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    if serve_flag || port_var.is_some() {
        let port = port_var.unwrap_or(8080);
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
        let local_addr = listener.local_addr()?;
        let issuer = format!("http://127.0.0.1:{}", local_addr.port());
        let (app, _) = build_app(issuer).await?;
        println!("READY: listening on http://127.0.0.1:{}", local_addr.port());
        let _ = std::io::stdout().flush();
        tracing::info!("Server listening on http://127.0.0.1:{}", local_addr.port());
        axum::serve(listener, app).await?;
    } else {
        println!("Running in-memory automated self-test...");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let issuer = format!("http://127.0.0.1:{}", addr.port());
        // Synthetic step-up claim minting is isolated strictly to this in-process self-test.
        let (app, _) = build_app_with_mode(issuer.clone(), true).await?;

        println!("READY: listening on http://{addr}");
        let _ = std::io::stdout().flush();
        tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::error!(error = %err, "in-process OIDC DPoP test server stopped with error");
            }
        });

        run_automated_self_test(addr, &issuer).await?;
        println!("All OIDC + DPoP + Step-Up automated tests passed successfully!");
    }

    Ok(())
}

/// Generates an RSA-2048 private key in PKCS#8 PEM format for OP token signing.
fn generate_rsa_pem() -> AppResult<Vec<u8>> {
    let mut rng = rand::rngs::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)?;
    Ok(private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?
        .as_bytes()
        .to_vec())
}

/// Generates a test EC P-256 keypair for client DPoP proofs.
fn generate_client_dpop_key() -> AppResult<(EncodingKey, Jwk)> {
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pem = secret.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?;
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes())?;
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)?;
    Ok((encoding_key, jwk))
}

/// Builds an RFC 9449 DPoP proof JWS.
fn build_dpop_proof(
    key: &EncodingKey,
    jwk: &Jwk,
    htm: &str,
    htu: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
    jti: &str,
) -> AppResult<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(jwk.clone());

    let mut claims = serde_json::json!({
        "htm": htm,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
        "jti": jti,
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::json!(n);
    }
    if let Some(tok) = access_token {
        let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(tok.as_bytes()));
        claims["ath"] = serde_json::json!(ath);
    }

    Ok(jsonwebtoken::encode(&header, &claims, key)?)
}

async fn run_automated_self_test(addr: SocketAddr, issuer: &str) -> AppResult<()> {
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // 1. Discovery verification
    println!("Step 1: Verifying OIDC Discovery");
    let disc_res = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await?;
    assert_eq!(disc_res.status(), StatusCode::OK);
    let disc_json: serde_json::Value = disc_res.json().await?;
    assert_eq!(disc_json["issuer"], issuer);
    assert_eq!(disc_json["token_endpoint"], format!("{issuer}/token"));

    // 2. JWKS verification
    println!("Step 2: Verifying JWKS endpoints (/jwks and /jwks.json)");
    let jwks_res = client.get(format!("{base}/jwks.json")).send().await?;
    assert_eq!(jwks_res.status(), StatusCode::OK);
    let jwks_json: serde_json::Value = jwks_res.json().await?;
    assert!(jwks_json["keys"].as_array().is_some_and(|k| !k.is_empty()));

    let (dpop_key, dpop_jwk) = generate_client_dpop_key()?;

    // 3. /token with DPoP proof missing nonce -> expect HTTP 400 use_dpop_nonce + DPoP-Nonce header
    println!(
        "Step 3: Calling /token with DPoP proof missing nonce -> expect HTTP 400 use_dpop_nonce"
    );
    let proof_no_nonce = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{base}/token"),
        None,
        None,
        "jti-1",
    )?;
    let no_nonce_res = client
        .post(format!("{base}/token"))
        .header("DPoP", proof_no_nonce)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await?;
    assert_eq!(no_nonce_res.status(), StatusCode::BAD_REQUEST);
    let dpop_nonce_header = no_nonce_res
        .headers()
        .get("dpop-nonce")
        .ok_or("must return dpop-nonce header on use_dpop_nonce refusal")?
        .to_str()?
        .to_string();
    assert!(!dpop_nonce_header.is_empty());
    let err_json: serde_json::Value = no_nonce_res.json().await?;
    assert_eq!(err_json["error"], "use_dpop_nonce");

    // 4. /token with invalid/stale nonce -> expect HTTP 400 use_dpop_nonce + fresh DPoP-Nonce
    println!("Step 4: Calling /token with invalid nonce -> expect HTTP 400 use_dpop_nonce + fresh DPoP-Nonce");
    let proof_invalid_nonce = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{base}/token"),
        Some("stale_invalid_nonce_value"),
        None,
        "jti-stale",
    )?;
    let invalid_nonce_res = client
        .post(format!("{base}/token"))
        .header("DPoP", proof_invalid_nonce)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await?;
    assert_eq!(invalid_nonce_res.status(), StatusCode::BAD_REQUEST);
    let fresh_nonce = invalid_nonce_res
        .headers()
        .get("dpop-nonce")
        .ok_or("must carry fresh dpop-nonce")?
        .to_str()?
        .to_string();
    let err_invalid: serde_json::Value = invalid_nonce_res.json().await?;
    assert_eq!(err_invalid["error"], "use_dpop_nonce");

    // 5. /token with valid DPoP proof carrying server nonce
    println!("Step 5: Calling /token with valid DPoP proof + fresh nonce -> expect HTTP 200 OK + DPoP-Nonce");
    let proof_with_nonce = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{base}/token"),
        Some(&fresh_nonce),
        None,
        "jti-2",
    )?;
    let token_res = client
        .post(format!("{base}/token"))
        .header("DPoP", proof_with_nonce)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await?;
    assert_eq!(token_res.status(), StatusCode::OK);
    assert!(
        token_res.headers().get("dpop-nonce").is_some(),
        "successful token response must include next DPoP-Nonce"
    );
    let token_json: serde_json::Value = token_res.json().await?;
    assert_eq!(token_json["token_type"], "DPoP");
    let access_token = token_json["access_token"]
        .as_str()
        .ok_or("missing access_token in token response")?
        .to_string();

    // 6. Access /api/high-value-action before step-up -> expect HTTP 401 insufficient_user_authentication
    println!("Step 6: Calling /api/high-value-action before step-up -> expect HTTP 401 insufficient_user_authentication");
    let proof_api_1 = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{base}/api/high-value-action"),
        None,
        Some(&access_token),
        "jti-3",
    )?;
    let action_res_1 = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", proof_api_1)
        .send()
        .await?;
    assert_eq!(action_res_1.status(), StatusCode::UNAUTHORIZED);
    let www_auth = action_res_1
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .ok_or("WWW-Authenticate header present")?
        .to_str()?;
    assert!(www_auth.contains("insufficient_user_authentication"));
    assert!(www_auth.contains("acr_values=\"2\""));
    let action_err: serde_json::Value = action_res_1.json().await?;
    assert_eq!(action_err["error"], "insufficient_user_authentication");

    // 7. Perform step-up via POST /api/step-up (self-test mode only)
    println!(
        "Step 7: Performing step-up via POST /api/step-up -> expect HTTP 200 OK + elevated token"
    );
    let proof_stepup = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "POST",
        &format!("{base}/api/step-up"),
        None,
        Some(&access_token),
        "jti-4",
    )?;
    let stepup_res = client
        .post(format!("{base}/api/step-up"))
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", proof_stepup)
        .send()
        .await?;
    assert_eq!(stepup_res.status(), StatusCode::OK);
    let stepup_json: serde_json::Value = stepup_res.json().await?;
    assert_eq!(stepup_json["token_type"], "DPoP");
    assert_eq!(stepup_json["acr"], "2");
    let elevated_token = stepup_json["access_token"]
        .as_str()
        .ok_or("missing elevated access_token")?
        .to_string();

    // 8. Access /api/high-value-action after step-up -> expect HTTP 200 OK
    println!("Step 8: Calling /api/high-value-action with elevated token -> expect HTTP 200 OK");
    let proof_api_2 = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        &format!("{base}/api/high-value-action"),
        None,
        Some(&elevated_token),
        "jti-5",
    )?;
    let action_res_2 = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {elevated_token}"))
        .header("DPoP", &proof_api_2)
        .send()
        .await?;
    assert_eq!(action_res_2.status(), StatusCode::OK);
    let action_ok: serde_json::Value = action_res_2.json().await?;
    assert_eq!(action_ok["status"], "success");
    assert_eq!(action_ok["acr"], "2");

    // 9. Replay the same DPoP proof (jti-5) -> expect HTTP 401 invalid_dpop_proof
    println!("Step 9: Replaying DPoP proof -> expect HTTP 401 invalid_dpop_proof");
    let replay_res = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {elevated_token}"))
        .header("DPoP", proof_api_2)
        .send()
        .await?;
    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);
    let replay_err: serde_json::Value = replay_res.json().await?;
    assert_eq!(replay_err["error"], "invalid_dpop_proof");

    // 10. Wrong htu in DPoP proof -> expect HTTP 401 invalid_dpop_proof
    println!("Step 10: Wrong htu in DPoP proof -> expect HTTP 401 invalid_dpop_proof");
    let wrong_htu_proof = build_dpop_proof(
        &dpop_key,
        &dpop_jwk,
        "GET",
        "https://wrong-host.example/api/high-value-action",
        None,
        Some(&elevated_token),
        "jti-6",
    )?;
    let wrong_htu_res = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {elevated_token}"))
        .header("DPoP", wrong_htu_proof)
        .send()
        .await?;
    assert_eq!(wrong_htu_res.status(), StatusCode::UNAUTHORIZED);
    let wrong_htu_err: serde_json::Value = wrong_htu_res.json().await?;
    assert_eq!(wrong_htu_err["error"], "invalid_dpop_proof");

    // 11. Verify public build_app / --serve configuration disables synthetic /api/step-up minting
    println!("Step 11: Verifying build_app (--serve config) refuses synthetic /api/step-up -> expect HTTP 403 step_up_verification_required");
    let serve_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let serve_addr = serve_listener.local_addr()?;
    let serve_base = format!("http://{serve_addr}");
    let (serve_app, _) = build_app(serve_base.clone()).await?;
    let serve_handle = tokio::spawn(async move {
        if let Err(err) = axum::serve(serve_listener, serve_app).await {
            tracing::error!(error = %err, "serve verification listener stopped with error");
        }
    });

    let serve_nonce_res = client
        .post(format!("{serve_base}/token"))
        .header(
            "DPoP",
            build_dpop_proof(
                &dpop_key,
                &dpop_jwk,
                "POST",
                &format!("{serve_base}/token"),
                None,
                None,
                "jti-serve-1",
            )?,
        )
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await?;
    assert_eq!(serve_nonce_res.status(), StatusCode::BAD_REQUEST);
    let serve_nonce = serve_nonce_res
        .headers()
        .get("dpop-nonce")
        .ok_or("serve token endpoint must return dpop-nonce header")?
        .to_str()?
        .to_string();

    let serve_token_res = client
        .post(format!("{serve_base}/token"))
        .header(
            "DPoP",
            build_dpop_proof(
                &dpop_key,
                &dpop_jwk,
                "POST",
                &format!("{serve_base}/token"),
                Some(&serve_nonce),
                None,
                "jti-serve-2",
            )?,
        )
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await?;
    assert_eq!(serve_token_res.status(), StatusCode::OK);
    let serve_token_json: serde_json::Value = serve_token_res.json().await?;
    let serve_token = serve_token_json["access_token"]
        .as_str()
        .ok_or("missing access_token from serve instance")?;

    let serve_stepup_res = client
        .post(format!("{serve_base}/api/step-up"))
        .header("Authorization", format!("DPoP {serve_token}"))
        .header(
            "DPoP",
            build_dpop_proof(
                &dpop_key,
                &dpop_jwk,
                "POST",
                &format!("{serve_base}/api/step-up"),
                None,
                Some(serve_token),
                "jti-serve-3",
            )?,
        )
        .send()
        .await?;
    assert_eq!(serve_stepup_res.status(), StatusCode::FORBIDDEN);
    let serve_stepup_err: serde_json::Value = serve_stepup_res.json().await?;
    assert_eq!(serve_stepup_err["error"], "step_up_verification_required");
    serve_handle.abort();

    Ok(())
}

/// Resolves the token signing secret dynamically: checks `AUTHKESTRA_TOKEN_SECRET` then
/// `JWT_SECRET` for the first valid secret of at least 32 bytes, falling back to a securely
/// generated random 32-byte secret at startup (CWE-321).
pub fn resolve_token_secret() -> Vec<u8> {
    for var_name in ["AUTHKESTRA_TOKEN_SECRET", "JWT_SECRET"] {
        if let Ok(val) = std::env::var(var_name) {
            let bytes = val.into_bytes();
            if bytes.len() >= 32 {
                tracing::debug!(
                    source = var_name,
                    "resolved token signing secret from environment"
                );
                return bytes;
            }
            tracing::warn!(
                source = var_name,
                "ignoring token secret environment variable shorter than 32 bytes"
            );
        }
    }
    tracing::warn!(
        "AUTHKESTRA_TOKEN_SECRET and JWT_SECRET unset or invalid; generating ephemeral CSPRNG secret"
    );
    let mut key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}
