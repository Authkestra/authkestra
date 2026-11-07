use super::*;
use crate::client::{ClientRegistration, GrantType};
use authkestra_engine::store::KvStore;

use crate::device::{DeviceCodeSession, DeviceCodeStatus, DeviceCodeStore};
use crate::handlers::token::tests::{test_config, test_tokens};

use authkestra_engine::auth::state::Identity;
use chrono::{Duration, Utc};
use std::collections::HashMap;

fn default_device_req(device_code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        code: None,
        redirect_uri: None,
        client_id: Some("client1".to_string()),
        client_secret: None,
        code_verifier: None,
        scope: None,
        refresh_token: None,
        device_code: Some(device_code.to_string()),
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        audience: None,
        client_assertion: None,
        client_assertion_type: None,
        dpop_jkt: None,
    }
}

fn test_identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user1".to_string(),
        username: Some("user1".to_string()),
        email: None,
        attributes: HashMap::new(),
    }
}

async fn setup_store(
    status: DeviceCodeStatus,
    client_id: &str,
    scope: &str,
) -> (
    authkestra_engine::store::memory::MemoryStore<crate::device::DeviceCodeSession>,
    authkestra_engine::store::memory::MemoryStore<crate::client::ClientRegistration>,
) {
    let mut devices =
        authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new();
    let session = DeviceCodeSession::new(
        "dev123".to_string(),
        "USER123".to_string(),
        client_id.to_string(),
        scope.to_string(),
        Utc::now() + Duration::seconds(600),
        status,
    );
    devices.store_device_code(session).await.unwrap();

    let clients =
        authkestra_engine::store::memory::MemoryStore::<crate::client::ClientRegistration>::new();
    clients
        .set(
            "client1",
            ClientRegistration {
                client_id: "client1".to_string(),
                client_secret_hash: None,
                redirect_uris: vec![],
                grant_types: vec![GrantType::DeviceCode],
                scopes: scope.split_whitespace().map(|s| s.to_string()).collect(),
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    (devices, clients)
}

#[tokio::test]
async fn test_device_denied() {
    let (devices, clients) = setup_store(DeviceCodeStatus::Denied, "client1", "openid").await;
    let req = default_device_req("dev123");

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients.clone(),
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            devices.clone(),
        ),
        &test_tokens(),
    )
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().error, "access_denied");
}

#[tokio::test]
async fn test_device_wrong_client() {
    let (devices, clients) = setup_store(
        DeviceCodeStatus::Approved(test_identity()),
        "client2",
        "openid",
    )
    .await;
    let req = default_device_req("dev123"); // requests with client1

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients.clone(),
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            devices.clone(),
        ),
        &test_tokens(),
    )
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().error, "invalid_grant");
}

#[tokio::test]
async fn test_device_expired() {
    let mut devices =
        authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new();
    let session = DeviceCodeSession::new(
        "dev123".to_string(),
        "USER123".to_string(),
        "client1".to_string(),
        "openid".to_string(),
        Utc::now() - Duration::seconds(600), // Expired
        DeviceCodeStatus::Approved(test_identity()),
    );
    devices.store_device_code(session).await.unwrap();

    let clients =
        authkestra_engine::store::memory::MemoryStore::<crate::client::ClientRegistration>::new();
    clients
        .set(
            "client1",
            ClientRegistration {
                client_id: "client1".to_string(),
                client_secret_hash: None,
                redirect_uris: vec![],
                grant_types: vec![GrantType::DeviceCode],
                scopes: vec![],
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let req = default_device_req("dev123");

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients.clone(),
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            devices.clone(),
        ),
        &test_tokens(),
    )
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().error, "expired_token");
}

#[tokio::test]
async fn test_device_offline_access() {
    let (devices, clients) = setup_store(
        DeviceCodeStatus::Approved(test_identity()),
        "client1",
        "openid offline_access",
    )
    .await;
    let req = default_device_req("dev123");

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &mut crate::store::CompositeOpStore::new(
            clients.clone(),
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            devices.clone(),
        ),
        &test_tokens(),
    )
    .await;

    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.refresh_token.is_some());
}

#[tokio::test]
async fn test_device_concurrency() {
    let mut devices =
        authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new();
    let session = DeviceCodeSession::new(
        "dev123".to_string(),
        "USER123".to_string(),
        "client1".to_string(),
        "openid".to_string(),
        Utc::now() + Duration::seconds(600),
        DeviceCodeStatus::Approved(test_identity()),
    );
    devices.store_device_code(session).await.unwrap();
    let devices = std::sync::Arc::new(devices);

    let clients = std::sync::Arc::new(authkestra_engine::store::memory::MemoryStore::<
        crate::client::ClientRegistration,
    >::new());
    clients
        .set(
            "client1",
            ClientRegistration {
                client_id: "client1".to_string(),
                client_secret_hash: None,
                redirect_uris: vec![],
                grant_types: vec![GrantType::DeviceCode],
                scopes: vec!["openid".to_string()],
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let config = std::sync::Arc::new(test_config(false));
    let tokens = std::sync::Arc::new(test_tokens());

    let mut handles = vec![];

    for _ in 0..10 {
        let devices = devices.clone();
        let clients = clients.clone();
        let config = config.clone();
        let tokens = tokens.clone();

        handles.push(tokio::spawn(async move {
            let req = default_device_req("dev123");
            handle_token(
                req,
                None,
                &config,
                &mut crate::store::CompositeOpStore::new(
                    (*clients).clone(),
                    authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
                    authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
                    (*devices).clone(),
                ),
                &tokens,
            )
            .await
        }));
    }

    let mut successes = 0;
    let mut invalid_grants = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(e) if e.error == "invalid_grant" => invalid_grants += 1,
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    assert_eq!(successes, 1, "Exactly one request should succeed");
    assert_eq!(
        invalid_grants, 9,
        "All other requests should fail with invalid_grant"
    );
}

/// Verifies that an invalid scope on an approved device code returns `invalid_scope`
/// before consuming the device code, leaving it redeemable once the scope is allowed.
#[tokio::test]
async fn test_device_flow_invalid_scope_does_not_consume_code() {
    let mut devices =
        authkestra_engine::store::memory::MemoryStore::<crate::device::DeviceCodeSession>::new();
    let session = DeviceCodeSession::new(
        "dev_scope_1".to_string(),
        "USRSCP".to_string(),
        "client1".to_string(),
        "openid admin".to_string(),
        Utc::now() + Duration::seconds(600),
        DeviceCodeStatus::Approved(test_identity()),
    );
    devices.store_device_code(session).await.unwrap();

    let clients =
        authkestra_engine::store::memory::MemoryStore::<crate::client::ClientRegistration>::new();
    clients
        .set(
            "client1",
            ClientRegistration {
                client_id: "client1".to_string(),
                client_secret_hash: None,
                redirect_uris: vec![],
                grant_types: vec![GrantType::DeviceCode],
                scopes: vec!["openid".to_string()], // "admin" not yet allowed
                require_pkce: false,
                allowed_audiences: vec![],
                token_endpoint_auth_method: None,
                jwks: None,
            },
            std::time::Duration::from_secs(31536000),
        )
        .await
        .unwrap();

    let mut config = test_config(false);
    config.scopes_supported = vec!["openid".to_string(), "admin".to_string()];
    let tokens = test_tokens();

    let err = handle_token(
        default_device_req("dev_scope_1"),
        None,
        &config,
        &mut crate::store::CompositeOpStore::new(
            clients.clone(),
            authkestra_engine::store::memory::MemoryStore::<crate::code::AuthorizationCode>::new(),
            authkestra_engine::store::memory::MemoryStore::<crate::refresh::RefreshToken>::new(),
            devices.clone(),
        ),
        &tokens,
    )
    .await
    .unwrap_err();
    assert_eq!(err.error, "invalid_scope");

    // Device code must still be present in store (not consumed)
    assert!(devices
        .get_device_code("dev_scope_1")
        .await
        .unwrap()
        .is_some());
}
