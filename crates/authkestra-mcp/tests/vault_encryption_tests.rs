use authkestra_crypto_util::{encrypt_aes_256_gcm, CryptoError};
use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::memory::MemoryStore;
use authkestra_engine::store::KvStore;
use authkestra_mcp::{
    BrokerError, DownstreamToken, DownstreamTokenBroker, EncryptedKvTokenVault, ToolContext,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn make_identity(provider: &str, user_id: &str) -> Identity {
    Identity {
        provider_id: provider.to_string(),
        external_id: user_id.to_string(),
        email: Some(format!("{user_id}@{provider}.com")),
        username: Some(user_id.to_string()),
        attributes: HashMap::new(),
    }
}

const VAULT_KEY: [u8; 32] = [77u8; 32];

#[tokio::test]
async fn test_at_rest_encryption_and_plaintext_absence() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), VAULT_KEY);

    let alice = make_identity("github_corp", "alice_dev");
    let secret_token_str = "gho_SUPER_SECRET_PLAINTEXT_TOKEN_ABC123";

    let token = DownstreamToken {
        access_token: secret_token_str.to_string(),
        refresh_token: Some("ghr_REFRESH_TOKEN_XYZ987".to_string()),
        token_type: "Bearer".to_string(),
        scopes: vec!["repo".to_string(), "read:org".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    // 1. Store token in vault
    vault
        .store_token(&alice, "github", &token, Duration::from_secs(3600))
        .await
        .expect("store succeeds");

    // 2. Query underlying raw store directly
    let storage_key = EncryptedKvTokenVault::storage_key(&alice, "github");
    let raw_bytes = raw_store
        .get(&storage_key)
        .await
        .expect("read raw store")
        .expect("entry must exist");

    // 3. Objectively verify raw bytes DO NOT contain plaintext substrings!
    let raw_lossy = String::from_utf8_lossy(&raw_bytes);
    assert!(
        !raw_lossy.contains("gho_SUPER_SECRET_PLAINTEXT_TOKEN_ABC123"),
        "raw storage bytes MUST NOT contain plaintext access token!"
    );
    assert!(
        !raw_lossy.contains("ghr_REFRESH_TOKEN_XYZ987"),
        "raw storage bytes MUST NOT contain plaintext refresh token!"
    );

    // 4. Verify round-trip resolution for owning identity succeeds
    let resolved = vault
        .resolve_token(&alice, "github", &["repo"])
        .await
        .expect("resolution succeeds")
        .expect("token resolved");

    assert_eq!(resolved, secret_token_str);
}

#[tokio::test]
async fn test_cross_identity_vault_isolation() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(raw_store, VAULT_KEY);

    let alice = make_identity("tenant_a", "alice");
    let mallory = make_identity("tenant_a", "mallory");

    let token = DownstreamToken {
        access_token: "alice_secret_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["admin".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    vault
        .store_token(&alice, "aws", &token, Duration::from_secs(3600))
        .await
        .unwrap();

    // Mallory attempting to resolve Alice's token receives None
    let mallory_result = vault
        .resolve_token(&mallory, "aws", &["admin"])
        .await
        .unwrap();

    assert_eq!(mallory_result, None);
}

#[tokio::test]
async fn test_ambiguous_legacy_tuples_are_isolated_for_all_operations() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = Arc::new(EncryptedKvTokenVault::new(raw_store, VAULT_KEY));
    let owner = make_identity("corp:dept", "user:svc");
    let other_provider = make_identity("corp", "dept:user:svc");
    let other_service = make_identity("corp:dept", "user");
    let token = DownstreamToken {
        access_token: "owner-token".into(),
        refresh_token: None,
        token_type: "Bearer".into(),
        scopes: vec!["read".into()],
        expires_at: None,
    };
    vault
        .store_token(&owner, "api", &token, Duration::from_secs(60))
        .await
        .unwrap();

    // Both alternate tuples had the same legacy key as the owner.
    for (identity, service) in [(&other_provider, "api"), (&other_service, "svc:api")] {
        let context = ToolContext::new("session")
            .with_identity(identity.clone())
            .with_broker(vault.clone());
        assert_eq!(
            context
                .get_downstream_token(service, &["read"])
                .await
                .unwrap(),
            None
        );
        vault.revoke_token(identity, service).await.unwrap();
    }
    let mut other_token = token.clone();
    other_token.access_token = "other-token".into();
    vault
        .store_token(
            &other_service,
            "svc:api",
            &other_token,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(
        vault
            .resolve_token(&owner, "api", &["read"])
            .await
            .unwrap()
            .as_deref(),
        Some("owner-token")
    );
    assert_eq!(
        vault
            .resolve_token(&other_service, "svc:api", &["read"])
            .await
            .unwrap()
            .as_deref(),
        Some("other-token")
    );
}

#[tokio::test]
async fn test_copied_ciphertext_is_rejected_for_each_binding_component() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), VAULT_KEY);
    let owner = make_identity("corp", "alice");
    let token = DownstreamToken {
        access_token: "owner-token".into(),
        refresh_token: None,
        token_type: "Bearer".into(),
        scopes: vec![],
        expires_at: None,
    };
    vault
        .store_token(&owner, "api", &token, Duration::from_secs(60))
        .await
        .unwrap();
    let ciphertext = raw_store
        .get(&EncryptedKvTokenVault::storage_key(&owner, "api"))
        .await
        .unwrap()
        .unwrap();
    for (identity, service) in [
        (make_identity("other", "alice"), "api"),
        (make_identity("corp", "bob"), "api"),
        (owner.clone(), "other"),
    ] {
        raw_store
            .set(
                &EncryptedKvTokenVault::storage_key(&identity, service),
                ciphertext.clone(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert!(matches!(
            vault.resolve_token(&identity, service, &[]).await,
            Err(BrokerError::RecordMismatch)
        ));
    }
}

#[tokio::test]
async fn test_legacy_records_are_not_resolved_or_revoked() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), VAULT_KEY);
    let identity = make_identity("corp", "alice");
    let token = DownstreamToken {
        access_token: "legacy-token".into(),
        refresh_token: None,
        token_type: "Bearer".into(),
        scopes: vec![],
        expires_at: None,
    };
    let legacy_key = "mcp:vault:corp:alice:api";
    let ciphertext = encrypt_aes_256_gcm(&serde_json::to_vec(&token).unwrap(), &VAULT_KEY).unwrap();
    raw_store
        .set(legacy_key, ciphertext, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        vault.resolve_token(&identity, "api", &[]).await.unwrap(),
        None
    );
    vault.revoke_token(&identity, "api").await.unwrap();
    assert!(raw_store.get(legacy_key).await.unwrap().is_some());
}

#[tokio::test]
async fn test_ciphertext_tampering_rejected_by_aead() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), VAULT_KEY);

    let alice = make_identity("corp", "alice");
    let token = DownstreamToken {
        access_token: "tamper_test_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["read".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    vault
        .store_token(&alice, "service_x", &token, Duration::from_secs(3600))
        .await
        .unwrap();

    let storage_key = EncryptedKvTokenVault::storage_key(&alice, "service_x");
    let mut raw_bytes = raw_store.get(&storage_key).await.unwrap().unwrap();

    // Flip 1 byte in the ciphertext payload
    let last_idx = raw_bytes.len() - 1;
    raw_bytes[last_idx] ^= 0x01;
    raw_store
        .set(&storage_key, raw_bytes, Duration::from_secs(3600))
        .await
        .unwrap();

    // Decryption must fail due to AEAD tag verification failure
    let err = vault
        .resolve_token(&alice, "service_x", &["read"])
        .await
        .expect_err("tampered ciphertext must fail AEAD authentication");

    assert!(matches!(
        err,
        BrokerError::Crypto(CryptoError::Decryption(_))
    ));
}

#[tokio::test]
async fn test_insufficient_downstream_scope_rejected() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(raw_store, VAULT_KEY);

    let alice = make_identity("corp", "alice");
    let token = DownstreamToken {
        access_token: "read_only_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["read:users".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    vault
        .store_token(&alice, "api", &token, Duration::from_secs(3600))
        .await
        .unwrap();

    // Requesting write scope must return InsufficientScope
    let err = vault
        .resolve_token(&alice, "api", &["write:users"])
        .await
        .expect_err("must reject missing scopes");

    assert!(matches!(err, BrokerError::InsufficientScope { .. }));
}

#[tokio::test]
async fn test_expired_downstream_token_rejected() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(raw_store, VAULT_KEY);

    let alice = make_identity("corp", "alice");
    let token = DownstreamToken {
        access_token: "expired_token".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["read".to_string()],
        expires_at: Some(Utc::now().timestamp() - 10), // Expired 10 seconds ago
    };

    vault
        .store_token(&alice, "api", &token, Duration::from_secs(3600))
        .await
        .unwrap();

    let err = vault
        .resolve_token(&alice, "api", &["read"])
        .await
        .expect_err("must reject expired token");

    assert!(matches!(err, BrokerError::TokenExpired(_)));
}

#[tokio::test]
async fn test_token_revocation() {
    let raw_store: Arc<dyn KvStore<Vec<u8>>> = Arc::new(MemoryStore::new());
    let vault = EncryptedKvTokenVault::new(Arc::clone(&raw_store), VAULT_KEY);

    let alice = make_identity("corp", "alice");
    let token = DownstreamToken {
        access_token: "token_to_revoke".to_string(),
        refresh_token: None,
        token_type: "Bearer".to_string(),
        scopes: vec!["read".to_string()],
        expires_at: Some(Utc::now().timestamp() + 3600),
    };

    vault
        .store_token(&alice, "api", &token, Duration::from_secs(3600))
        .await
        .unwrap();

    // Revoke
    vault.revoke_token(&alice, "api").await.unwrap();

    // Now resolve returns None
    let res = vault.resolve_token(&alice, "api", &["read"]).await.unwrap();
    assert_eq!(res, None);
}
