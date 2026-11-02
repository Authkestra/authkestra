//! What a user grant's access token carries (authkestra#421): the client's configured audiences
//! as `aud`, the client in `client_id`, and the RFC 9068 `at+jwt` type, through the token endpoint
//! itself for the authorization-code, refresh-token and device-code grants. The ID token keeps the
//! client as its only audience.

use super::*;
use crate::client::{ClientRegistration, GrantType};
use crate::code::{AuthorizationCode, AuthorizationCodeStore};
use crate::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use crate::handlers::token::tests::{test_config, test_tokens};
use crate::refresh::RefreshTokenStore;
use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use authkestra_engine::token::{Audience, Claims};
use base64::Engine;
use chrono::{Duration, Utc};
use std::collections::HashMap;

const AUDIENCES: [&str; 2] = ["api-a", "api-b"];

fn identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user1".to_string(),
        username: Some("user1".to_string()),
        email: None,
        attributes: HashMap::new(),
    }
}

fn client(grant_types: Vec<GrantType>, allowed_audiences: &[&str]) -> ClientRegistration {
    ClientRegistration {
        client_id: "client1".to_string(),
        client_secret_hash: None,
        redirect_uris: vec!["https://cb".to_string()],
        grant_types,
        scopes: vec!["openid".to_string(), "offline_access".to_string()],
        require_pkce: false,
        allowed_audiences: allowed_audiences.iter().map(|a| (*a).to_string()).collect(),
        token_endpoint_auth_method: None,
        jwks: None,
    }
}

async fn clients(client: ClientRegistration) -> MemoryStore<ClientRegistration> {
    let clients = MemoryStore::<ClientRegistration>::new();
    clients
        .set("client1", client, std::time::Duration::from_secs(3600))
        .await
        .unwrap();
    clients
}

fn request(grant_type: &str) -> TokenRequest {
    TokenRequest {
        grant_type: grant_type.to_string(),
        code: None,
        redirect_uri: None,
        client_id: Some("client1".to_string()),
        client_secret: None,
        code_verifier: None,
        scope: None,
        refresh_token: None,
        subject_token: None,
        subject_token_type: None,
        device_code: None,
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        audience: None,
        client_assertion: None,
        client_assertion_type: None,
        dpop_jkt: None,
    }
}

/// The `typ` header and the verified claims of a token this OP issued.
fn inspect(token: &str) -> (Option<String>, Claims) {
    let typ = jsonwebtoken::decode_header(token).unwrap().typ;
    let claims = test_tokens().validate_token(token, None).unwrap();
    (typ, claims)
}

fn assert_access_token(token: &str, audience: Audience) {
    let (typ, claims) = inspect(token);
    assert_eq!(typ.as_deref(), Some("at+jwt"));
    assert_eq!(claims.aud, Some(audience));
    assert_eq!(
        claims.extra.get("client_id"),
        Some(&serde_json::json!("client1"))
    );
    assert_eq!(claims.sub, "user1");
}

fn configured() -> Audience {
    Audience::Multiple(AUDIENCES.iter().map(|a| (*a).to_string()).collect())
}

/// An authorization-code exchange for a client with `allowed_audiences`.
async fn authorization_code(allowed_audiences: &[&str]) -> TokenResponse {
    let verifier = "audience-test-verifier";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let mut codes = MemoryStore::<AuthorizationCode>::new();
    let mut code = AuthorizationCode::new(
        "code-audience".to_string(),
        "client1".to_string(),
        "https://cb".to_string(),
        "openid".to_string(),
        identity(),
        Utc::now() + Duration::minutes(5),
        false,
    );
    code.code_challenge = Some(challenge);
    code.code_challenge_method = Some("S256".to_string());
    codes.store_code(code).await.unwrap();

    handle_token(
        TokenRequest {
            code: Some("code-audience".to_string()),
            redirect_uri: Some("https://cb".to_string()),
            code_verifier: Some(verifier.to_string()),
            ..request("authorization_code")
        },
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients(client(
                vec![GrantType::AuthorizationCode],
                allowed_audiences,
            ))
            .await,
            codes,
            MemoryStore::<RefreshToken>::new(),
            MemoryStore::<DeviceCodeSession>::new(),
        ),
        &test_tokens(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn an_authorization_code_grant_names_the_configured_audiences_and_the_client() {
    let response = authorization_code(&AUDIENCES).await;
    assert_access_token(&response.access_token, configured());

    // The ID token is for the client: its audience stays the client id, and it is not typed as
    // an access token.
    let (typ, claims) = inspect(response.id_token.as_deref().expect("openid scope"));
    assert_ne!(typ.as_deref(), Some("at+jwt"));
    assert_eq!(claims.aud, Some(Audience::Single("client1".to_string())));
}

#[tokio::test]
async fn without_configured_audiences_the_access_token_is_for_the_client_as_before() {
    let response = authorization_code(&[]).await;
    assert_access_token(
        &response.access_token,
        Audience::Single("client1".to_string()),
    );
}

#[tokio::test]
async fn a_refreshed_access_token_keeps_the_configured_audiences_and_the_client() {
    let mut refresh = MemoryStore::<RefreshToken>::new();
    refresh
        .store_token(RefreshToken::new(
            "rt-audience".to_string(),
            "client1".to_string(),
            identity(),
            "openid".to_string(),
            Utc::now() + Duration::days(1),
            None,
        ))
        .await
        .unwrap();

    let response = handle_token(
        TokenRequest {
            refresh_token: Some("rt-audience".to_string()),
            ..request("refresh_token")
        },
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients(client(vec![GrantType::RefreshToken], &AUDIENCES)).await,
            MemoryStore::<AuthorizationCode>::new(),
            refresh,
            MemoryStore::<DeviceCodeSession>::new(),
        ),
        &test_tokens(),
    )
    .await
    .unwrap();

    assert_access_token(&response.access_token, configured());
}

#[tokio::test]
async fn a_device_code_grant_names_the_configured_audiences_and_the_client() {
    let mut devices = MemoryStore::<DeviceCodeSession>::new();
    devices
        .store_device_code(DeviceCodeSession::new(
            "dev-audience".to_string(),
            "USERCODE".to_string(),
            "client1".to_string(),
            "openid".to_string(),
            Utc::now() + Duration::seconds(600),
            DeviceCodeStatus::Approved(identity()),
        ))
        .await
        .unwrap();

    let response = handle_token(
        TokenRequest {
            device_code: Some("dev-audience".to_string()),
            ..request("urn:ietf:params:oauth:grant-type:device_code")
        },
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients(client(vec![GrantType::DeviceCode], &AUDIENCES)).await,
            MemoryStore::<AuthorizationCode>::new(),
            MemoryStore::<RefreshToken>::new(),
            devices,
        ),
        &test_tokens(),
    )
    .await
    .unwrap();

    assert_access_token(&response.access_token, configured());
}
