//! RFC 9449 §8 DPoP nonces at `/token`, through the actix handler: the
//! `use_dpop_nonce` refusal carries a `DPoP-Nonce`, the retry with it
//! succeeds, and a store without nonces (the default) behaves as before.

use std::sync::Arc;

use actix_web::{test, web, App};
use authkestra_actix::op::actix_token_handler;
use authkestra_engine::oauth2::client::{ClientRegistration, GrantType};
use authkestra_engine::oauth2::code::AuthorizationCode;
use authkestra_engine::oauth2::device::DeviceCodeSession;
use authkestra_engine::oauth2::refresh::RefreshToken;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use authkestra_engine::token::dpop_nonce::DpopNonces;
use authkestra_engine::TokenManager;
use authkestra_op::store::CompositeOpStore;
use authkestra_op::{CloneableOpStore, DpopJtiRecord, OpConfig};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header};

const ISSUER: &str = "https://auth.example.com";
const CLIENT_ID: &str = "nonce-client";

/// A fixed test-only P-256 key for the proofs. It protects nothing.
const PROOF_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkY9zPQCZIf1NMDnK
44MN+AmCVP/JTC4OEBjtcJMah8ahRANCAAQBjtX7ev4QV+DwqUrBLOFOwBnVngju
ZaoTPr5K9e2ZNnz4FLjxxXr+cvkIuwdO83BpSPWdfGmUgQsj22fqefan
-----END PRIVATE KEY-----
";

async fn state(
    nonces: Option<DpopNonces>,
) -> (Arc<dyn CloneableOpStore>, Arc<TokenManager>, OpConfig) {
    let clients = MemoryStore::<ClientRegistration>::new();
    #[allow(deprecated)] // require_pkce (authkestra#273)
    clients
        .set(
            CLIENT_ID,
            ClientRegistration {
                client_id: CLIENT_ID.to_string(),
                client_secret_hash: None,
                redirect_uris: vec![],
                grant_types: vec![GrantType::ClientCredentials],
                scopes: vec!["custom".to_string()],
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap();
    let store = CompositeOpStore::new(
        clients,
        MemoryStore::<AuthorizationCode>::new(),
        MemoryStore::<RefreshToken>::new(),
        MemoryStore::<DeviceCodeSession>::new(),
    )
    .with_dpop_replay_store(MemoryStore::<DpopJtiRecord>::new());
    let op_store: Arc<dyn CloneableOpStore> = match nonces {
        Some(nonces) => Arc::new(store.with_dpop_nonces(nonces)),
        None => Arc::new(store),
    };
    (
        op_store,
        Arc::new(TokenManager::new(
            b"super_secret_key_that_is_long_enough_for_hmac",
            None,
        )),
        OpConfig {
            issuer: ISSUER.to_string(),
            scopes_supported: vec!["custom".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["client_credentials".to_string()],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 600,
            token_exchange_enabled: false,
        },
    )
}

fn proof(jti: &str, nonce: Option<&str>) -> String {
    let key = EncodingKey::from_ec_pem(PROOF_KEY.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(Jwk::from_encoding_key(&key, Algorithm::ES256).unwrap());
    let mut claims = serde_json::json!({
        "htm": "POST",
        "htu": format!("{ISSUER}/token"),
        "iat": chrono::Utc::now().timestamp(),
        "jti": jti,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = serde_json::json!(nonce);
    }
    jsonwebtoken::encode(&header, &claims, &key).unwrap()
}

macro_rules! service {
    ($nonces:expr) => {{
        let (op_store, tokens, config) = state($nonces).await;
        test::init_service(
            App::new()
                .app_data(web::Data::new(op_store))
                .app_data(web::Data::new(tokens))
                .app_data(web::Data::new(config))
                .route("/token", web::post().to(actix_token_handler)),
        )
        .await
    }};
}

fn token_request(proof: &str) -> test::TestRequest {
    test::TestRequest::post()
        .uri("/token")
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .insert_header(("DPoP", proof))
        .set_payload(format!(
            "grant_type=client_credentials&client_id={CLIENT_ID}&scope=custom"
        ))
}

#[actix_web::test]
async fn use_dpop_nonce_then_the_retry_with_the_served_nonce_succeeds() {
    let app = service!(Some(DpopNonces::random(std::time::Duration::from_secs(
        300
    ))));

    let refused = test::call_service(&app, token_request(&proof("jti-1", None)).to_request()).await;
    assert_eq!(refused.status(), 400);
    let nonce = refused
        .headers()
        .get("dpop-nonce")
        .expect("a use_dpop_nonce refusal must carry a DPoP-Nonce")
        .to_str()
        .unwrap()
        .to_owned();
    let body: serde_json::Value = test::read_body_json(refused).await;
    assert_eq!(body["error"], "use_dpop_nonce");

    let accepted = test::call_service(
        &app,
        token_request(&proof("jti-2", Some(&nonce))).to_request(),
    )
    .await;
    assert_eq!(accepted.status(), 200);
    assert!(
        accepted.headers().get("dpop-nonce").is_some(),
        "a success carries the next nonce too"
    );
    let body: serde_json::Value = test::read_body_json(accepted).await;
    assert_eq!(body["token_type"], "DPoP");
}

#[actix_web::test]
async fn without_nonces_a_proof_needs_none_and_no_header_is_sent() {
    let app = service!(None);
    let resp = test::call_service(&app, token_request(&proof("jti-3", None)).to_request()).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("dpop-nonce").is_none());
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["token_type"], "DPoP");
}
