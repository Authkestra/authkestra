//! # Actix Device/Service Attestation (Enrolment + Re-issuance) Example
//!
//! Actix counterpart of `axum/op_server_attestation.rs` — same ceremony
//! (spec §5.6/§5.6.1), same in-memory `EnrolmentChallengeStore`, wired
//! through `authkestra-actix`'s real route handlers instead of Axum's. See
//! that file for the full walkthrough of what each step does; this one only
//! documents where Actix's wiring differs.
//!
//! No external services required — run with:
//!
//! ```sh
//! cargo run -p authkestra --example actix_op_server_attestation --features full
//! ```

use actix_web::{web, App, HttpServer};
use async_trait::async_trait;
use authkestra::Authkestra;
use authkestra_actix::op::{
    actix_complete_challenge_handler, actix_enrol_start_handler, actix_reissue_start_handler,
    OpActixExt,
};
use authkestra_engine::store::memory::MemoryStore;
use authkestra_op::attestation::{
    AttestationConfig, EnrolmentChallenge, PrincipalType, SecondFactorProof, SecondFactorVerifier,
};
use authkestra_op::client::ClientRegistration;
use authkestra_op::code::AuthorizationCode;
use authkestra_op::device::DeviceCodeSession;
use authkestra_op::refresh::RefreshToken;
use authkestra_op::store::CompositeOpStore;
use authkestra_op::Op;
use authkestra_op::OpError;
use base64::Engine as Base64Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::{JwkEcKey, PublicKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;

/// A stand-in second factor for this example: validates the claimed subject identity,
/// principal type, and accepts one fixed demo OTP for the authorized demonstration.
/// See `axum/op_server_attestation.rs`'s `DemoOtpVerifier` for the same
/// rationale — this is the identical trait impl, duplicated here rather
/// than shared, matching how every other example pair in this crate
/// (`axum/op_server.rs` vs. `actix/op_server.rs`) is self-contained.
pub struct DemoOtpVerifier;

#[async_trait]
impl SecondFactorVerifier for DemoOtpVerifier {
    async fn verify(
        &self,
        subject: &str,
        principal_type: PrincipalType,
        proof: &SecondFactorProof,
    ) -> Result<(), OpError> {
        // Enforce expected demo subject and principal type to prevent unauthorized
        // key enrollment under arbitrary identities (CWE-287 / Rows 1, 14).
        if subject.trim().is_empty() || subject != "user-42" {
            tracing::warn!(subject = %subject, "DemoOtpVerifier rejected unauthorized or empty subject");
            return Err(OpError::SecondFactorFailed);
        }

        if principal_type != PrincipalType::Device {
            tracing::warn!(principal_type = ?principal_type, "DemoOtpVerifier rejected unauthorized principal type");
            return Err(OpError::SecondFactorFailed);
        }

        if proof.kind == "demo_otp" && proof.value == "123456" {
            tracing::debug!(subject = %subject, principal_type = ?principal_type, "DemoOtpVerifier verified second factor successfully");
            Ok(())
        } else {
            tracing::warn!("DemoOtpVerifier rejected invalid second-factor proof");
            Err(OpError::SecondFactorFailed)
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let issuer = "https://op.example.test".to_string();
    // The token manager's `iss` claim must equal `OpConfig::issuer` below, or relying parties
    // reject the tokens this OP mints.
    let token_secret = resolve_token_secret();
    let engine = Authkestra::builder()
        .session_store(Arc::new(MemoryStore::<
            authkestra_engine::auth::session::Session,
        >::new()))
        .token_manager(Arc::new(authkestra::core::TokenManager::new(
            &token_secret,
            Some(issuer.clone()),
        )))
        .build();

    let op_store: Arc<dyn authkestra_op::CloneableOpStore> = Arc::new(CompositeOpStore::new(
        MemoryStore::<ClientRegistration>::new(),
        MemoryStore::<AuthorizationCode>::new(),
        MemoryStore::<RefreshToken>::new(),
        MemoryStore::<DeviceCodeSession>::new(),
    ));

    let op = Op::builder()
        .engine(engine)
        .config(authkestra_op::config::OpConfig {
            issuer,
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            id_token_signing_alg: "ES256".to_string(),
            authorization_code_ttl_secs: 600,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        })
        .store(op_store)
        .challenge_store(Arc::new(MemoryStore::<EnrolmentChallenge>::new()))
        .second_factor_verifier(Arc::new(DemoOtpVerifier))
        .attestation_config(AttestationConfig::new())
        .build();

    // Fixed port: unlike Axum's `TcpListener::bind`, `HttpServer::bind`
    // does not hand back an ephemeral port trivially before `run()`, and
    // this example does not need one — pick a port distinct from the other
    // OP examples (`op_server.rs` uses 8080) so both can run side by side.
    let port = port_from_env();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let server = HttpServer::new(move || {
        let op = op.clone();
        App::new()
            .configure(move |cfg| {
                cfg.configure_op(op.clone());
            })
            // No AttestationStatusProvider registered: re-issuance falls
            // back to copying the previous `att` claim forward (see that
            // trait's docs). `Option<web::Data<...>>` resolves to `None`
            // when nothing is registered under that type.
            .route("/enrol", web::post().to(actix_enrol_start_handler))
            .route(
                "/enrol/complete",
                web::post().to(actix_complete_challenge_handler),
            )
            .route("/reissue", web::post().to(actix_reissue_start_handler))
    })
    .bind(addr)?
    .run();

    tracing::info!("Actix attestation-issuance OP running on http://{addr}");
    tokio::spawn(server);

    run_client_demo(addr).await;
    Ok(())
}

/// Plays the part of a device: generates a keypair, enrols it, and then
/// re-issues the resulting attestation once.
async fn run_client_demo(addr: SocketAddr) {
    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let (device_key_der, device_jwk) = generate_device_key();

    // --- Step 1: enrol a brand-new device key (spec §5.6 steps 1-3) -----
    tracing::info!("\n== enrolling a new device ==");
    let enrol_body = serde_json::json!({
        "subject": "user-42",
        "principal_id": "device-abc123",
        "principal_type": "device",
        "public_jwk": device_jwk,
        "attributes": { "kyc_level": "verified" },
        "second_factor": { "kind": "demo_otp", "value": "123456" },
    });
    let challenge: serde_json::Value = client
        .post(format!("{base}/enrol"))
        .json(&enrol_body)
        .send()
        .await
        .expect("POST /enrol failed")
        .error_for_status()
        .expect("POST /enrol returned an error status")
        .json()
        .await
        .expect("POST /enrol did not return JSON");
    let challenge_value = challenge["challenge"]
        .as_str()
        .expect("challenge response missing `challenge`")
        .to_string();
    tracing::info!("received single-use challenge: {challenge_value}");

    let signature = sign_challenge(&device_key_der, &challenge_value);
    let attestation = complete_challenge(&client, &base, &challenge_value, &signature).await;
    print_attestation("initial enrolment", &attestation);

    // --- Step 2: silently re-issue before expiry (ADR 0014 point 6) ----
    tracing::info!("\n== re-issuing the attestation with the same key ==");
    let reissue_body = serde_json::json!({
        "attestation": attestation["attestation"],
        "public_jwk": device_jwk,
    });
    let reissue_challenge: serde_json::Value = client
        .post(format!("{base}/reissue"))
        .json(&reissue_body)
        .send()
        .await
        .expect("POST /reissue failed")
        .error_for_status()
        .expect("POST /reissue returned an error status")
        .json()
        .await
        .expect("POST /reissue did not return JSON");
    let reissue_challenge_value = reissue_challenge["challenge"]
        .as_str()
        .expect("reissue response missing `challenge`")
        .to_string();

    let reissue_signature = sign_challenge(&device_key_der, &reissue_challenge_value);
    let renewed =
        complete_challenge(&client, &base, &reissue_challenge_value, &reissue_signature).await;
    print_attestation("re-issuance", &renewed);
}

/// POSTs `/enrol/complete` — shared by both the enrolment and re-issuance
/// steps, since completion is the same operation either way.
async fn complete_challenge(
    client: &reqwest::Client,
    base: &str,
    challenge: &str,
    challenge_signature: &str,
) -> serde_json::Value {
    client
        .post(format!("{base}/enrol/complete"))
        .json(&serde_json::json!({
            "challenge": challenge,
            "challenge_signature": challenge_signature,
        }))
        .send()
        .await
        .expect("POST /enrol/complete failed")
        .error_for_status()
        .expect("POST /enrol/complete returned an error status")
        .json()
        .await
        .expect("POST /enrol/complete did not return JSON")
}

/// Generates a fresh EC P-256 keypair and returns (PKCS#8 DER-encoded
/// private key, public JWK as JSON).
fn generate_device_key() -> (Vec<u8>, serde_json::Value) {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_key: PublicKey<p256::NistP256> = signing_key.verifying_key().into();
    let jwk_ec_key = JwkEcKey::from(&public_key);
    let public_jwk = serde_json::to_value(&jwk_ec_key).expect("jwk always serializes");
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .expect("key always encodes to pkcs8")
        .as_bytes()
        .to_vec();
    (pkcs8_der, public_jwk)
}

/// Signs `{"challenge": challenge}` with the device's private key.
fn sign_challenge(pkcs8_der: &[u8], challenge: &str) -> String {
    let encoding_key = EncodingKey::from_ec_der(pkcs8_der);
    let header = Header::new(Algorithm::ES256);
    jsonwebtoken::encode(
        &header,
        &serde_json::json!({ "challenge": challenge }),
        &encoding_key,
    )
    .expect("signing with a freshly generated key never fails")
}

/// Prints the issued attestation's lifetime and decodes its (unverified)
/// payload purely for display.
fn print_attestation(step: &str, resp: &serde_json::Value) {
    tracing::info!(
        "[{step}] expires_in={}s reissue_after={}",
        resp["expires_in"],
        resp["reissue_after"]
    );
    let attestation = resp["attestation"]
        .as_str()
        .expect("attestation response missing `attestation`");
    let payload_b64 = attestation
        .split('.')
        .nth(1)
        .expect("a compact JWS always has a payload segment");
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("JWS payload is always valid base64url");
    let claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("attestation payload is always JSON");
    tracing::info!(
        "[{step}] claims: {}",
        serde_json::to_string_pretty(&claims).expect("claims always serialize")
    );
}

/// Bind port, overridable via `PORT` so examples can run without colliding.
fn port_from_env() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8092)
}

/// Resolves the token signing secret dynamically: checks `AUTHKESTRA_TOKEN_SECRET` then
/// `JWT_SECRET` for the first valid secret of at least 32 bytes, falling back to a securely
/// generated random 32-byte secret at startup so no static source literal can forge tokens (CWE-321).
pub fn resolve_token_secret() -> Vec<u8> {
    for var_name in ["AUTHKESTRA_TOKEN_SECRET", "JWT_SECRET"] {
        if let Ok(val) = std::env::var(var_name) {
            let bytes = val.into_bytes();
            if bytes.len() >= 32 {
                tracing::info!(
                    var = var_name,
                    "Using token signing secret from environment variable"
                );
                return bytes;
            }
            tracing::warn!(
                var = var_name,
                "Configured token secret from environment is shorter than 32 bytes; checking fallback or ephemeral key"
            );
        }
    }
    tracing::info!("Generating random 32-byte secret for example token signing");
    let mut key = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut key);
    key
}
