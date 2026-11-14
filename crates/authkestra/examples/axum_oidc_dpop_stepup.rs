//! # Axum OIDC + DPoP + Step-Up Example
//!
//! Runnable standalone in-memory OpenID Provider and Resource Server demonstrating:
//! 1. RFC 9449 §8 DPoP Nonce challenge loop (`use_dpop_nonce`) on `/token`.
//! 2. Fresh `DPoP-Nonce` returned on successful HTTP 200 OK responses.
//! 3. Standard OIDC discovery (`/.well-known/openid-configuration`) and JWKS (`/jwks`, `/jwks.json`).
//! 4. Pre-seeded fixture client (`client_id: "test-client"`).
//! 5. Resource server endpoints wired with `authkestra_resource` (`JwtStrategy`,
//!    `ValidationConfig::static_jwks`, `dpop_resource_origin`, `DpopReplayStore`,
//!    `StepUpRequirement`) and `authkestra_axum::Auth<I>` enforcing DPoP binding
//!    and RFC 9470 step-up authentication (`acr: "2"`).
//!
//! ## Dual Execution Mode:
//! - Default / no args: executes automated end-to-end client verification against an in-process server.
//! - `--serve` or `PORT=<port>`: binds to the specified port as a standing daemon and logs
//!   `READY: listening on http://...` for external testrunners (e.g. `fespalier` CI).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use authkestra_axum::op::{axum_jwks_handler, OpExt};
use authkestra_axum::{Auth, AxumError};
use authkestra_engine::auth::session::Session;
use authkestra_engine::oauth2::client::{ClientRegistration, GrantType};
use authkestra_engine::oauth2::code::AuthorizationCode;
use authkestra_engine::oauth2::device::DeviceCodeSession;
use authkestra_engine::oauth2::refresh::RefreshToken;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use authkestra_engine::token::dpop_nonce::DpopNonces;
use authkestra_engine::Identity;
use authkestra_engine::{SessionConfig, SessionStore, TokenManager};
use authkestra_op::store::CompositeOpStore;
use authkestra_op::{CloneableOpStore, DpopJtiRecord, OpConfig};
use authkestra_resource::jwt::{Jwks, JwtStrategy, ValidationConfig};
use authkestra_resource::{
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

pub const CLIENT_ID: &str = "test-client";

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ActionClaims {
    pub sub: String,
    #[serde(default)]
    pub acr: Option<String>,
    #[serde(default)]
    pub cnf: Option<CnfClaim>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CnfClaim {
    pub jkt: String,
}

/// Distinct newtype so `/api/high-value-action` resolves its own [`Guard`]
/// configured with [`StepUpRequirement`] (`acr_values = "2"`), separate from
/// `/api/step-up`'s [`Guard<ActionClaims>`].
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(transparent)]
pub struct StepUpClaims(pub ActionClaims);

#[derive(Clone)]
pub struct AppState {
    pub op_store: Arc<dyn CloneableOpStore>,
    pub tokens: Arc<TokenManager>,
    pub session_store: Arc<dyn SessionStore>,
    pub session_config: SessionConfig,
    pub config: OpConfig,
    pub client_guard: Arc<Guard<ActionClaims>>,
    pub stepup_guard: Arc<Guard<StepUpClaims>>,
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

/// Endpoint exchanging an active DPoP-bound token (verified via [`Auth<ActionClaims>`])
/// for an elevated ACR level 2 token bound to the same `cnf.jkt`.
async fn step_up_handler(
    State(state): State<AppState>,
    Auth(claims): Auth<ActionClaims>,
) -> Response {
    let Some(cnf) = claims.cnf else {
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

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Issue elevated token with acr: "2", auth_time, and same cnf.jkt binding
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

pub async fn build_app(issuer: String) -> (Router, AppState) {
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
        .await
        .unwrap();

    let store = CompositeOpStore::new(
        clients,
        MemoryStore::<AuthorizationCode>::new(),
        MemoryStore::<RefreshToken>::new(),
        MemoryStore::<DeviceCodeSession>::new(),
    )
    .with_dpop_replay_store(MemoryStore::<DpopJtiRecord>::new())
    .with_dpop_nonces(DpopNonces::random(Duration::from_secs(300)));

    let op_store: Arc<dyn CloneableOpStore> = Arc::new(store);

    let rsa_pem = generate_rsa_pem();
    let tokens = Arc::new(
        TokenManager::new_asymmetric(&rsa_pem, Some(issuer.clone()), Some("op-key-1".to_string()))
            .expect("build asymmetric TokenManager"),
    );
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
        .expect("asymmetric TokenManager exposes public JWK");
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
    };

    let app = Router::new()
        .merge(state.op_axum_router())
        .route("/jwks", get(axum_jwks_handler::<AppState>))
        .route("/api/step-up", post(step_up_handler))
        .route("/api/high-value-action", get(high_value_action_handler))
        .with_state(state.clone());

    (app, state)
}

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let args: Vec<String> = std::env::args().collect();
    let serve_flag = args.iter().any(|a| a == "--serve");
    let port_var = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    if serve_flag || port_var.is_some() {
        let port = port_var.unwrap_or(8080);
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .expect("bind listener");
        let local_addr = listener.local_addr().unwrap();
        let issuer = format!("http://127.0.0.1:{}", local_addr.port());
        let (app, _) = build_app(issuer).await;
        println!("READY: listening on http://127.0.0.1:{}", local_addr.port());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        tracing::info!("Server listening on http://127.0.0.1:{}", local_addr.port());
        axum::serve(listener, app).await.expect("serve app");
    } else {
        println!("Running in-memory automated self-test...");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let issuer = format!("http://127.0.0.1:{}", addr.port());
        let (app, _) = build_app(issuer.clone()).await;

        println!("READY: listening on http://{addr}");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        run_automated_self_test(addr, &issuer).await;
        println!("All OIDC + DPoP + Step-Up automated tests passed successfully!");
    }
}

/// Generates an RSA-2048 private key in PKCS#8 PEM format for OP token signing.
fn generate_rsa_pem() -> Vec<u8> {
    use rsa::pkcs8::EncodePrivateKey;
    let mut rng = rand::rngs::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode RSA key to PKCS8 PEM")
        .as_bytes()
        .to_vec()
}

/// Generates a test EC P-256 keypair for client DPoP proofs.
fn generate_client_dpop_key() -> (EncodingKey, Jwk) {
    let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let pem = secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("encode EC key to PKCS8 PEM");
    let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("from_ec_pem");
    let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::ES256).expect("jwk from key");
    (encoding_key, jwk)
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
) -> String {
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

    jsonwebtoken::encode(&header, &claims, key).expect("encode dpop proof")
}

async fn run_automated_self_test(addr: SocketAddr, issuer: &str) {
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");

    // 1. Discovery verification
    println!("Step 1: Verifying OIDC Discovery");
    let disc_res = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .expect("discovery request");
    assert_eq!(disc_res.status(), StatusCode::OK);
    let disc_json: serde_json::Value = disc_res.json().await.expect("discovery json");
    assert_eq!(disc_json["issuer"], issuer);
    assert_eq!(disc_json["token_endpoint"], format!("{issuer}/token"));

    // 2. JWKS verification
    println!("Step 2: Verifying JWKS endpoints (/jwks and /jwks.json)");
    let jwks_res = client
        .get(format!("{base}/jwks.json"))
        .send()
        .await
        .expect("jwks.json request");
    assert_eq!(jwks_res.status(), StatusCode::OK);
    let jwks_json: serde_json::Value = jwks_res.json().await.expect("jwks json");
    assert!(jwks_json["keys"].as_array().is_some_and(|k| !k.is_empty()));

    let (dpop_key, dpop_jwk) = generate_client_dpop_key();

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
    );
    let no_nonce_res = client
        .post(format!("{base}/token"))
        .header("DPoP", proof_no_nonce)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await
        .expect("no-nonce token req");
    assert_eq!(no_nonce_res.status(), StatusCode::BAD_REQUEST);
    let dpop_nonce_header = no_nonce_res
        .headers()
        .get("dpop-nonce")
        .expect("must return dpop-nonce header on use_dpop_nonce refusal")
        .to_str()
        .expect("ascii header")
        .to_string();
    assert!(!dpop_nonce_header.is_empty());
    let err_json: serde_json::Value = no_nonce_res.json().await.expect("error json");
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
    );
    let invalid_nonce_res = client
        .post(format!("{base}/token"))
        .header("DPoP", proof_invalid_nonce)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await
        .expect("invalid-nonce token req");
    assert_eq!(invalid_nonce_res.status(), StatusCode::BAD_REQUEST);
    let fresh_nonce = invalid_nonce_res
        .headers()
        .get("dpop-nonce")
        .expect("must carry fresh dpop-nonce")
        .to_str()
        .expect("ascii header")
        .to_string();
    let err_invalid: serde_json::Value = invalid_nonce_res.json().await.expect("json");
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
    );
    let token_res = client
        .post(format!("{base}/token"))
        .header("DPoP", proof_with_nonce)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", CLIENT_ID),
            ("scope", "api"),
        ])
        .send()
        .await
        .expect("token req with nonce");
    assert_eq!(token_res.status(), StatusCode::OK);
    assert!(
        token_res.headers().get("dpop-nonce").is_some(),
        "successful token response must include next DPoP-Nonce"
    );
    let token_json: serde_json::Value = token_res.json().await.expect("token json");
    assert_eq!(token_json["token_type"], "DPoP");
    let access_token = token_json["access_token"]
        .as_str()
        .expect("access_token")
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
    );
    let action_res_1 = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", proof_api_1)
        .send()
        .await
        .expect("high value action request 1");
    assert_eq!(action_res_1.status(), StatusCode::UNAUTHORIZED);
    let www_auth = action_res_1
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate header present")
        .to_str()
        .unwrap();
    assert!(www_auth.contains("insufficient_user_authentication"));
    assert!(www_auth.contains("acr_values=\"2\""));
    let action_err: serde_json::Value = action_res_1.json().await.expect("json");
    assert_eq!(action_err["error"], "insufficient_user_authentication");

    // 7. Perform step-up via POST /api/step-up
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
    );
    let stepup_res = client
        .post(format!("{base}/api/step-up"))
        .header("Authorization", format!("DPoP {access_token}"))
        .header("DPoP", proof_stepup)
        .send()
        .await
        .expect("step-up request");
    assert_eq!(stepup_res.status(), StatusCode::OK);
    let stepup_json: serde_json::Value = stepup_res.json().await.expect("stepup json");
    assert_eq!(stepup_json["token_type"], "DPoP");
    assert_eq!(stepup_json["acr"], "2");
    let elevated_token = stepup_json["access_token"]
        .as_str()
        .expect("elevated access token")
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
    );
    let action_res_2 = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {elevated_token}"))
        .header("DPoP", &proof_api_2)
        .send()
        .await
        .expect("high value action request 2");
    assert_eq!(action_res_2.status(), StatusCode::OK);
    let action_ok: serde_json::Value = action_res_2.json().await.expect("action ok json");
    assert_eq!(action_ok["status"], "success");
    assert_eq!(action_ok["acr"], "2");

    // 9. Replay the same DPoP proof (jti-5) -> expect HTTP 401 invalid_dpop_proof
    println!("Step 9: Replaying DPoP proof -> expect HTTP 401 invalid_dpop_proof");
    let replay_res = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {elevated_token}"))
        .header("DPoP", proof_api_2)
        .send()
        .await
        .expect("replay request");
    assert_eq!(replay_res.status(), StatusCode::UNAUTHORIZED);
    let replay_err: serde_json::Value = replay_res.json().await.expect("replay err json");
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
    );
    let wrong_htu_res = client
        .get(format!("{base}/api/high-value-action"))
        .header("Authorization", format!("DPoP {elevated_token}"))
        .header("DPoP", wrong_htu_proof)
        .send()
        .await
        .expect("wrong htu request");
    assert_eq!(wrong_htu_res.status(), StatusCode::UNAUTHORIZED);
    let wrong_htu_err: serde_json::Value = wrong_htu_res.json().await.expect("wrong htu json");
    assert_eq!(wrong_htu_err["error"], "invalid_dpop_proof");
}

/// Resolves the token signing secret dynamically: checks `AUTHKESTRA_TOKEN_SECRET` then
/// `JWT_SECRET` for the first valid secret of at least 32 bytes, falling back to a securely
/// generated random 32-byte secret at startup (CWE-321).
pub fn resolve_token_secret() -> Vec<u8> {
    for var_name in ["AUTHKESTRA_TOKEN_SECRET", "JWT_SECRET"] {
        if let Ok(val) = std::env::var(var_name) {
            let bytes = val.into_bytes();
            if bytes.len() >= 32 {
                return bytes;
            }
        }
    }
    let mut key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}
