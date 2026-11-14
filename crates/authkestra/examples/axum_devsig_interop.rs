//! # Axum Device-Signature Interoperability CI Example
//!
//! Demonstrates the complete 5-stage lifecycle for `fespalier` and CrateStack CI:
//! `enrol -> sign -> renew on attestation_expired -> key_not_bound -> revoked`.
//!
//! ## Lifecycle Phases
//! 1. `enrol`: Enrols Key A (`ambient`) and Key B (`user_present`) via `op_axum_attestation_router()`.
//!    Both keys receive `cnf.jkt`-bound attestations with `"status": "active"` and matching `att.role`.
//! 2. `sign`: Signs `/api/action` with Key A (HTTP 200 OK). Signs `/api/step-up` with Key A (HTTP 401
//!    `insufficient_user_authentication`). Signs `/api/step-up` with Key B (HTTP 200 OK).
//! 3. `renew on attestation_expired`: Presents an expired attestation to `/api/action` (HTTP 401
//!    `attestation_expired`). Calls `/reissue` with proof of possession to receive a renewed attestation.
//!    Retries `/api/action` with the renewed attestation (HTTP 200 OK).
//! 4. `key_not_bound`: Presents Key A attestation with Key B request signature (HTTP 401 `key_not_bound`).
//! 5. `revoked`: Marks the device principal revoked in `AttestationStatusProvider`. Invokes `/reissue`
//!    with Key A. Asserts HTTP 403 Forbidden with exact profile v1 error `{"error": "device_revoked"}`!
//!
//! ## Execution Modes
//! - Default (no args): runs the complete automated 5-phase self-test in-process and exits with 0.
//! - `--serve` or `PORT=<port>`: binds as a standing daemon and logs `READY: listening on http://...`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use authkestra::Authkestra;
use authkestra_axum::devsig::{refusal_response, AuthDeviceSignature, DeviceSignatureLayer};
use authkestra_axum::op::{OpExt, OpState};
use authkestra_devsig::{InMemoryReplayStore, IssuerJwks, KeyRole, Refusal, VerifierConfig};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::TokenManager;
use authkestra_op::attestation::{
    AttestationConfig, AttestationStatusProvider, EnrolmentChallenge, PrincipalType,
    SecondFactorProof, SecondFactorVerifier,
};
use authkestra_op::client::ClientRegistration;
use authkestra_op::code::AuthorizationCode;
use authkestra_op::device::DeviceCodeSession;
use authkestra_op::refresh::RefreshToken;
use authkestra_op::store::CompositeOpStore;
use authkestra_op::{Op, OpError};
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{crypto, Algorithm, EncodingKey};
use p256::pkcs8::EncodePrivateKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

pub const ISSUER: &str = "https://op.example.test";
pub const AUDIENCE: &str = "fespalier-devsig-api";
pub const OP_KID: &str = "op-devsig-rsa-1";
pub const DEMO_SUBJECT: &str = "user-test";
pub const DEMO_DEVICE_ID: &str = "device-123";

// ---------------------------------------------------------------------------
// 1. Second-Factor Verifier
// ---------------------------------------------------------------------------

pub struct DemoOtpVerifier;

#[async_trait]
impl SecondFactorVerifier for DemoOtpVerifier {
    async fn verify(
        &self,
        subject: &str,
        principal_type: PrincipalType,
        proof: &SecondFactorProof,
        _attributes: &serde_json::Value,
    ) -> Result<(), OpError> {
        if subject.trim().is_empty() || subject != DEMO_SUBJECT {
            tracing::warn!(subject = %subject, "DemoOtpVerifier rejected unauthorized or empty subject");
            return Err(OpError::SecondFactorFailed);
        }

        if principal_type != PrincipalType::Device {
            tracing::warn!(principal_type = ?principal_type, "DemoOtpVerifier rejected unauthorized principal type");
            return Err(OpError::SecondFactorFailed);
        }

        if proof.kind == "demo_otp" && proof.value == "123456" {
            Ok(())
        } else {
            tracing::warn!("DemoOtpVerifier rejected invalid second-factor proof");
            Err(OpError::SecondFactorFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Revocation Store & AttestationStatusProvider
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct RevocationStore {
    revoked_devices: Arc<RwLock<HashSet<String>>>,
}

impl RevocationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn revoke(&self, principal_id: &str) {
        self.revoked_devices
            .write()
            .await
            .insert(principal_id.to_string());
    }

    pub async fn is_revoked(&self, principal_id: &str) -> bool {
        self.revoked_devices.read().await.contains(principal_id)
    }
}

#[async_trait]
impl AttestationStatusProvider for RevocationStore {
    async fn current_attributes(
        &self,
        _subject: &str,
        principal_id: &str,
        _principal_type: PrincipalType,
    ) -> Result<Option<serde_json::Value>, OpError> {
        if self.is_revoked(principal_id).await {
            Ok(None)
        } else {
            Ok(Some(serde_json::json!({
                "status": "active"
            })))
        }
    }
}

#[derive(Deserialize)]
struct RevokePayload {
    principal_id: String,
}

async fn test_revoke_handler(
    State(store): State<RevocationStore>,
    Json(payload): Json<RevokePayload>,
) -> Response {
    store.revoke(&payload.principal_id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "revoked",
            "principal_id": payload.principal_id,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// 3. Protected Resource API Handlers
// ---------------------------------------------------------------------------

async fn api_action_handler(
    AuthDeviceSignature(identity): AuthDeviceSignature,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "subject": identity.subject,
            "device": identity.device,
            "role": identity.key_role().as_str(),
        })),
    )
}

async fn api_step_up_handler(AuthDeviceSignature(identity): AuthDeviceSignature) -> Response {
    if identity.key_role() != KeyRole::UserPresent {
        return refusal_response(Refusal::insufficient_user_authentication());
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "action": "high_value_action_completed",
            "subject": identity.subject,
            "device": identity.device,
            "role": identity.key_role().as_str(),
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// 4. App Builder
// ---------------------------------------------------------------------------

pub struct ServerContext {
    pub app: Router,
    pub revocation_store: RevocationStore,
    pub op_rsa_key: EncodingKey,
    pub op_kid: String,
}

pub async fn build_app() -> ServerContext {
    // 1. Generate RSA-2048 keypair for the OP
    let mut rng = rand::rngs::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA-2048 key");
    let pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("encode RSA to PKCS8 PEM");
    let op_rsa_key = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("from_rsa_pem");
    let mut issuer_jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&op_rsa_key, Algorithm::RS256)
        .expect("derive public Jwk");
    issuer_jwk.common.key_id = Some(OP_KID.to_string());

    let token_manager = Arc::new(
        TokenManager::new_asymmetric(
            pem.as_bytes(),
            Some(ISSUER.to_string()),
            Some(OP_KID.to_string()),
        )
        .expect("valid asymmetric token manager"),
    );

    let engine = Authkestra::builder()
        .session_store(Arc::new(MemoryStore::<
            authkestra_engine::auth::session::Session,
        >::new()))
        .token_manager(token_manager)
        .build();

    let op_store: Arc<dyn authkestra_op::CloneableOpStore> = Arc::new(CompositeOpStore::new(
        MemoryStore::<ClientRegistration>::new(),
        MemoryStore::<AuthorizationCode>::new(),
        MemoryStore::<RefreshToken>::new(),
        MemoryStore::<DeviceCodeSession>::new(),
    ));

    let revocation_store = RevocationStore::new();

    let state = Op::builder()
        .engine(engine)
        .config(authkestra_op::config::OpConfig {
            issuer: ISSUER.to_string(),
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 600,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        })
        .store(op_store)
        .challenge_store(Arc::new(MemoryStore::<EnrolmentChallenge>::new()))
        .second_factor_verifier(Arc::new(DemoOtpVerifier))
        .status_provider(Arc::new(revocation_store.clone()))
        .attestation_config(AttestationConfig::new())
        .build();

    // 2. Set up DeviceSignatureLayer for protected routes
    let jwks = Arc::new(IssuerJwks::new());
    jwks.insert(ISSUER, OP_KID.to_string(), issuer_jwk).await;

    let verifier_config = VerifierConfig::new(
        [ISSUER],
        [Algorithm::ES256, Algorithm::RS256],
        Duration::from_secs(30),
        Duration::from_secs(300),
        AUDIENCE,
    );

    let replay_store: Arc<dyn authkestra_devsig::ReplayStore> =
        Arc::new(InMemoryReplayStore::default());

    let devsig = authkestra_devsig::DevSig::builder()
        .config(verifier_config)
        .jwks(jwks)
        .replay_store(replay_store)
        .build();
    let devsig_layer = DeviceSignatureLayer::from(devsig);

    // 3. Assemble routes
    let op_router = state
        .op_axum_attestation_router()
        .with_state(OpState(state));

    let api_router = Router::new()
        .route("/api/action", get(api_action_handler))
        .route("/api/step-up", post(api_step_up_handler))
        .layer(devsig_layer);

    let test_router = Router::new()
        .route("/test/revoke", post(test_revoke_handler))
        .with_state(revocation_store.clone());

    let app = Router::new()
        .merge(op_router)
        .merge(api_router)
        .merge(test_router);

    ServerContext {
        app,
        revocation_store,
        op_rsa_key,
        op_kid: OP_KID.to_string(),
    }
}

// ---------------------------------------------------------------------------
// 5. Client Test Fixture & Helpers
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DeviceKey {
    pub encoding_key: EncodingKey,
    pub public_jwk: serde_json::Value,
    pub thumbprint: String,
}

impl DeviceKey {
    pub fn generate() -> Self {
        let secret = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let pem = secret
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encode EC key to PKCS8 PEM");
        let encoding_key = EncodingKey::from_ec_pem(pem.as_bytes()).expect("from_ec_pem");
        let jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&encoding_key, Algorithm::ES256)
            .expect("derive device jwk");
        let thumbprint = jwk
            .thumbprint(jsonwebtoken::jwk::ThumbprintHash::SHA256)
            .expect("compute thumbprint");
        let public_jwk = serde_json::to_value(&jwk).expect("serialize device jwk");

        Self {
            encoding_key,
            public_jwk,
            thumbprint,
        }
    }

    pub fn sign_challenge(&self, challenge: &str) -> String {
        let header = jsonwebtoken::Header::new(Algorithm::ES256);
        jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "challenge": challenge }),
            &self.encoding_key,
        )
        .expect("sign challenge")
    }

    pub fn mint_signature(&self, method: &str, path: &str, body: Option<&[u8]>) -> String {
        let now = chrono::Utc::now().timestamp();
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "authkestra-devsig+jws",
            "jwk": self.public_jwk,
        });
        let mut claims = serde_json::json!({
            "iat": now,
            "exp": now + 90,
            "jti": uuid::Uuid::new_v4().to_string(),
            "mth": method,
            "pth": path,
            "aud": AUDIENCE,
        });
        if let Some(b) = body {
            claims["bdh"] = serde_json::json!(hex_sha256(b));
        }

        build_compact_jws(&header, &claims, |msg| {
            crypto::sign(msg, &self.encoding_key, Algorithm::ES256).expect("sign request")
        })
    }
}

fn build_compact_jws(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    sign: impl Fn(&[u8]) -> String,
) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("header json"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims json"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_b64 = sign(signing_input.as_bytes());
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

fn hex_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_unverified_claims(jws: &str) -> serde_json::Value {
    let payload_b64 = jws
        .split('.')
        .nth(1)
        .expect("JWS must have payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("base64url decode payload");
    serde_json::from_slice(&bytes).expect("JSON parse payload")
}

fn mint_expired_attestation(op_rsa_key: &EncodingKey, kid: &str, jkt: &str, role: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let header = serde_json::json!({
        "alg": "RS256",
        "kid": kid,
        "typ": "webank-attest+jws",
    });
    let claims = serde_json::json!({
        "iss": ISSUER,
        "sub": DEMO_SUBJECT,
        "cnf": { "jkt": jkt },
        "did": DEMO_DEVICE_ID,
        "iat": now - 3600,
        "exp": now - 100,
        "att": {
            "status": "active",
            "role": role,
        }
    });

    build_compact_jws(&header, &claims, |msg| {
        crypto::sign(msg, op_rsa_key, Algorithm::RS256).expect("sign expired attestation")
    })
}

// ---------------------------------------------------------------------------
// 6. Automated 5-Phase Self-Test
// ---------------------------------------------------------------------------

async fn run_automated_self_test(addr: SocketAddr, ctx: ServerContext) {
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    println!("\n=== Phase 1: enrol Key A (ambient) and Key B (user_present) ===");
    let key_a = DeviceKey::generate();
    let key_b = DeviceKey::generate();

    // 1.1 Enrol Key A (ambient)
    let enrol_a_req = client
        .post(format!("{base}/enrol"))
        .json(&serde_json::json!({
            "subject": DEMO_SUBJECT,
            "principal_id": DEMO_DEVICE_ID,
            "principal_type": "device",
            "role": "ambient",
            "public_jwk": key_a.public_jwk,
            "attributes": { "role": "ambient" },
            "second_factor": { "kind": "demo_otp", "value": "123456" }
        }))
        .send()
        .await
        .expect("enrol Key A req");
    assert_eq!(enrol_a_req.status(), StatusCode::OK);
    let enrol_a_json: serde_json::Value = enrol_a_req.json().await.unwrap();
    let challenge_a = enrol_a_json["challenge"]
        .as_str()
        .expect("challenge")
        .to_string();

    let sig_chal_a = key_a.sign_challenge(&challenge_a);
    let complete_a_req = client
        .post(format!("{base}/enrol/complete"))
        .json(&serde_json::json!({
            "challenge": challenge_a,
            "challenge_signature": sig_chal_a,
        }))
        .send()
        .await
        .expect("complete Key A req");
    assert_eq!(complete_a_req.status(), StatusCode::OK);
    let complete_a_json: serde_json::Value = complete_a_req.json().await.unwrap();
    let attestation_a = complete_a_json["attestation"]
        .as_str()
        .expect("attestation")
        .to_string();

    let claims_a = decode_unverified_claims(&attestation_a);
    assert_eq!(claims_a["att"]["status"], "active");
    assert_eq!(claims_a["att"]["role"], "ambient");
    assert_eq!(claims_a["cnf"]["jkt"], key_a.thumbprint);
    println!("✓ Key A enrolled with status active and role ambient");

    // 1.2 Enrol Key B (user_present)
    let enrol_b_req = client
        .post(format!("{base}/enrol"))
        .json(&serde_json::json!({
            "subject": DEMO_SUBJECT,
            "principal_id": DEMO_DEVICE_ID,
            "principal_type": "device",
            "role": "user_present",
            "public_jwk": key_b.public_jwk,
            "attributes": { "role": "user_present" },
            "second_factor": { "kind": "demo_otp", "value": "123456" }
        }))
        .send()
        .await
        .expect("enrol Key B req");
    assert_eq!(enrol_b_req.status(), StatusCode::OK);
    let enrol_b_json: serde_json::Value = enrol_b_req.json().await.unwrap();
    let challenge_b = enrol_b_json["challenge"]
        .as_str()
        .expect("challenge")
        .to_string();

    let sig_chal_b = key_b.sign_challenge(&challenge_b);
    let complete_b_req = client
        .post(format!("{base}/enrol/complete"))
        .json(&serde_json::json!({
            "challenge": challenge_b,
            "challenge_signature": sig_chal_b,
        }))
        .send()
        .await
        .expect("complete Key B req");
    assert_eq!(complete_b_req.status(), StatusCode::OK);
    let complete_b_json: serde_json::Value = complete_b_req.json().await.unwrap();
    let attestation_b = complete_b_json["attestation"]
        .as_str()
        .expect("attestation")
        .to_string();

    let claims_b = decode_unverified_claims(&attestation_b);
    assert_eq!(claims_b["att"]["status"], "active");
    assert_eq!(claims_b["att"]["role"], "user_present");
    assert_eq!(claims_b["cnf"]["jkt"], key_b.thumbprint);
    println!("✓ Key B enrolled with status active and role user_present");

    println!("\n=== Phase 2: sign (/api/action and /api/step-up) ===");
    // 2.1 Sign /api/action with Key A -> 200 OK
    let sig_action_a = key_a.mint_signature("GET", "/api/action", None);
    let action_res = client
        .get(format!("{base}/api/action"))
        .header("X-Signature", &sig_action_a)
        .header("X-Attestation", &attestation_a)
        .send()
        .await
        .expect("action req");
    assert_eq!(action_res.status(), StatusCode::OK);
    let action_json: serde_json::Value = action_res.json().await.unwrap();
    assert_eq!(action_json["status"], "ok");
    assert_eq!(action_json["role"], "ambient");
    println!("✓ /api/action signed with Key A succeeded (200 OK)");

    // 2.2 Sign /api/step-up with Key A -> 401 insufficient_user_authentication
    let stepup_body = b"{\"amount\":1000}";
    let sig_stepup_a = key_a.mint_signature("POST", "/api/step-up", Some(stepup_body));
    let stepup_a_res = client
        .post(format!("{base}/api/step-up"))
        .header("X-Signature", &sig_stepup_a)
        .header("X-Attestation", &attestation_a)
        .header(header::CONTENT_TYPE, "application/json")
        .body(stepup_body.to_vec())
        .send()
        .await
        .expect("stepup A req");
    assert_eq!(stepup_a_res.status(), StatusCode::UNAUTHORIZED);
    let www_auth = stepup_a_res
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(www_auth.contains("insufficient_user_authentication"));
    let err_a_json: serde_json::Value = stepup_a_res.json().await.unwrap();
    assert_eq!(err_a_json["error"], "insufficient_user_authentication");
    println!("✓ /api/step-up with Key A refused (401 insufficient_user_authentication)");

    // 2.3 Sign /api/step-up with Key B -> 200 OK
    let sig_stepup_b = key_b.mint_signature("POST", "/api/step-up", Some(stepup_body));
    let stepup_b_res = client
        .post(format!("{base}/api/step-up"))
        .header("X-Signature", &sig_stepup_b)
        .header("X-Attestation", &attestation_b)
        .header(header::CONTENT_TYPE, "application/json")
        .body(stepup_body.to_vec())
        .send()
        .await
        .expect("stepup B req");
    assert_eq!(stepup_b_res.status(), StatusCode::OK);
    let stepup_b_json: serde_json::Value = stepup_b_res.json().await.unwrap();
    assert_eq!(stepup_b_json["status"], "ok");
    assert_eq!(stepup_b_json["action"], "high_value_action_completed");
    assert_eq!(stepup_b_json["role"], "user_present");
    println!("✓ /api/step-up with Key B succeeded (200 OK)");

    println!("\n=== Phase 3: renew on attestation_expired ===");
    // 3.1 Send request with expired attestation -> 401 attestation_expired
    let expired_attestation =
        mint_expired_attestation(&ctx.op_rsa_key, &ctx.op_kid, &key_a.thumbprint, "ambient");
    let sig_expired = key_a.mint_signature("GET", "/api/action", None);
    let expired_res = client
        .get(format!("{base}/api/action"))
        .header("X-Signature", &sig_expired)
        .header("X-Attestation", &expired_attestation)
        .send()
        .await
        .expect("expired req");
    assert_eq!(expired_res.status(), StatusCode::UNAUTHORIZED);
    let www_auth_exp = expired_res
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(www_auth_exp.contains("attestation_expired"));
    let err_exp_json: serde_json::Value = expired_res.json().await.unwrap();
    assert_eq!(err_exp_json["error"], "attestation_expired");
    println!("✓ Expired attestation rejected (401 attestation_expired)");

    // 3.2 Invoke /reissue with proof of possession
    let reissue_req = client
        .post(format!("{base}/reissue"))
        .json(&serde_json::json!({
            "attestation": attestation_a,
            "public_jwk": key_a.public_jwk,
        }))
        .send()
        .await
        .expect("reissue req");
    assert_eq!(reissue_req.status(), StatusCode::OK);
    let reissue_json: serde_json::Value = reissue_req.json().await.unwrap();
    let reissue_chal = reissue_json["challenge"]
        .as_str()
        .expect("challenge")
        .to_string();

    let sig_reissue = key_a.sign_challenge(&reissue_chal);
    let complete_reissue_req = client
        .post(format!("{base}/enrol/complete"))
        .json(&serde_json::json!({
            "challenge": reissue_chal,
            "challenge_signature": sig_reissue,
        }))
        .send()
        .await
        .expect("complete reissue req");
    assert_eq!(complete_reissue_req.status(), StatusCode::OK);
    let complete_reissue_json: serde_json::Value = complete_reissue_req.json().await.unwrap();
    let renewed_attestation_a = complete_reissue_json["attestation"]
        .as_str()
        .expect("attestation")
        .to_string();

    // 3.3 Retry request with renewed attestation -> 200 OK
    let sig_renewed = key_a.mint_signature("GET", "/api/action", None);
    let renewed_action_res = client
        .get(format!("{base}/api/action"))
        .header("X-Signature", &sig_renewed)
        .header("X-Attestation", &renewed_attestation_a)
        .send()
        .await
        .expect("renewed action req");
    assert_eq!(renewed_action_res.status(), StatusCode::OK);
    println!("✓ Reissue and retry with renewed attestation succeeded (200 OK)");

    println!("\n=== Phase 4: key_not_bound ===");
    // Present Key A attestation with Key B signature
    let sig_mismatch = key_b.mint_signature("GET", "/api/action", None);
    let mismatch_res = client
        .get(format!("{base}/api/action"))
        .header("X-Signature", &sig_mismatch)
        .header("X-Attestation", &attestation_a)
        .send()
        .await
        .expect("key_not_bound req");
    assert_eq!(mismatch_res.status(), StatusCode::UNAUTHORIZED);
    let www_auth_bound = mismatch_res
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(www_auth_bound.contains("key_not_bound"));
    let err_bound_json: serde_json::Value = mismatch_res.json().await.unwrap();
    assert_eq!(err_bound_json["error"], "key_not_bound");
    println!("✓ Key mismatch rejected (401 key_not_bound)");

    println!("\n=== Phase 5: revoked ===");
    // 5.1 Call /test/revoke to mark device revoked
    let revoke_res = client
        .post(format!("{base}/test/revoke"))
        .json(&serde_json::json!({
            "principal_id": DEMO_DEVICE_ID
        }))
        .send()
        .await
        .expect("revoke req");
    assert_eq!(revoke_res.status(), StatusCode::OK);
    println!("✓ Device marked revoked in AttestationStatusProvider");

    // 5.2 Invoke /reissue -> asserts HTTP 403 {"error": "device_revoked"}
    let revoked_reissue = client
        .post(format!("{base}/reissue"))
        .json(&serde_json::json!({
            "attestation": renewed_attestation_a,
            "public_jwk": key_a.public_jwk,
        }))
        .send()
        .await
        .expect("revoked reissue req");
    assert_eq!(revoked_reissue.status(), StatusCode::FORBIDDEN);
    let revoked_json: serde_json::Value = revoked_reissue.json().await.unwrap();
    assert_eq!(revoked_json["error"], "device_revoked");
    println!("✓ Reissue for revoked device rejected with HTTP 403 device_revoked!");
}

// ---------------------------------------------------------------------------
// 7. Token Secret Resolver (for examples_hardening tests)
// ---------------------------------------------------------------------------

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
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}

// ---------------------------------------------------------------------------
// 8. Main Entrypoint
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::fmt::try_init();

    let args: Vec<String> = std::env::args().collect();
    let serve_flag = args.iter().any(|a| a == "--serve");
    let port_var = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok());

    if serve_flag || port_var.is_some() {
        let port = port_var.unwrap_or(3002);
        let ctx = build_app().await;
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .expect("bind listener");
        let local_addr = listener.local_addr().unwrap();
        println!("READY: listening on http://127.0.0.1:{}", local_addr.port());
        use std::io::Write;
        let _ = std::io::stdout().flush();
        tracing::info!(
            "DevSig server listening on http://127.0.0.1:{}",
            local_addr.port()
        );
        axum::serve(listener, ctx.app).await.expect("serve app");
    } else {
        println!("Running in-memory automated devsig 5-phase self-test...");
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind ephemeral listener");
        let addr = listener.local_addr().expect("listener local_addr");
        let ctx = build_app().await;

        println!("READY: listening on http://{addr}");
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let app = ctx.app.clone();
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        run_automated_self_test(addr, ctx).await;
        println!("\nAll 5 devsig lifecycle phases passed successfully!");
    }
}
