use crate::broker::{BrokerError, DownstreamToken, DownstreamTokenBroker};
use async_trait::async_trait;
use authkestra_crypto_util::{decrypt_aes_256_gcm, encrypt_aes_256_gcm};
use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::KvStore;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

/// Encrypted downstream token vault storing AES-256-GCM encrypted tokens at rest in `KvStore`.
///
/// Ensures that downstream API tokens (e.g. GitHub, Slack, Jira) are encrypted at rest
/// using authenticated encryption (AEAD), isolating credentials across tenant identities
/// and protecting them from exposure in persistent logs or raw store dumps.
pub struct EncryptedKvTokenVault {
    store: Arc<dyn KvStore<Vec<u8>>>,
    encryption_key: [u8; 32],
}

impl EncryptedKvTokenVault {
    /// Creates a new `EncryptedKvTokenVault` backed by `store` and encrypted with `encryption_key`.
    pub fn new(store: Arc<dyn KvStore<Vec<u8>>>, encryption_key: [u8; 32]) -> Self {
        Self {
            store,
            encryption_key,
        }
    }

    /// Derives the isolated storage key for an identity and service.
    pub fn storage_key(identity: &Identity, service: &str) -> String {
        format!(
            "mcp:vault:{}:{}:{}",
            identity.provider_id, identity.external_id, service
        )
    }
}

#[async_trait]
impl DownstreamTokenBroker for EncryptedKvTokenVault {
    async fn store_token(
        &self,
        identity: &Identity,
        service: &str,
        token: &DownstreamToken,
        ttl: Duration,
    ) -> Result<(), BrokerError> {
        tracing::debug!(
            provider_id = %identity.provider_id,
            external_id = %identity.external_id,
            service = %service,
            ttl_secs = ttl.as_secs(),
            "encrypting downstream token with AES-256-GCM for storage at rest"
        );

        let raw_json =
            serde_json::to_vec(token).map_err(|e| BrokerError::Serialization(e.to_string()))?;
        let encrypted_bytes = encrypt_aes_256_gcm(&raw_json, &self.encryption_key)?;

        let key = Self::storage_key(identity, service);
        self.store
            .set(&key, encrypted_bytes, ttl)
            .await
            .map_err(|e| BrokerError::Store(e.to_string()))?;

        tracing::info!(
            provider_id = %identity.provider_id,
            external_id = %identity.external_id,
            service = %service,
            "downstream token securely stored in encrypted vault"
        );
        Ok(())
    }

    async fn resolve_token(
        &self,
        identity: &Identity,
        service: &str,
        scopes: &[&str],
    ) -> Result<Option<String>, BrokerError> {
        let key = Self::storage_key(identity, service);
        let Some(encrypted_bytes) = self
            .store
            .get(&key)
            .await
            .map_err(|e| BrokerError::Store(e.to_string()))?
        else {
            tracing::debug!(
                provider_id = %identity.provider_id,
                external_id = %identity.external_id,
                service = %service,
                "no downstream token found in vault"
            );
            return Ok(None);
        };

        let decrypted_bytes = decrypt_aes_256_gcm(&encrypted_bytes, &self.encryption_key)?;
        let token: DownstreamToken = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| BrokerError::Serialization(e.to_string()))?;

        if let Some(exp) = token.expires_at {
            if Utc::now().timestamp() > exp {
                tracing::warn!(
                    service = %service,
                    expires_at = exp,
                    "downstream token in vault is expired"
                );
                return Err(BrokerError::TokenExpired(service.to_string()));
            }
        }

        for required in scopes {
            if !token.scopes.iter().any(|s| s == *required) {
                tracing::warn!(
                    service = %service,
                    required = *required,
                    granted = ?token.scopes,
                    "downstream token lacks requested scope"
                );
                return Err(BrokerError::InsufficientScope {
                    service: service.to_string(),
                    required: scopes.iter().map(|s| s.to_string()).collect(),
                    granted: token.scopes,
                });
            }
        }

        tracing::debug!(
            provider_id = %identity.provider_id,
            external_id = %identity.external_id,
            service = %service,
            "downstream token successfully resolved and validated"
        );
        Ok(Some(token.access_token))
    }

    async fn revoke_token(&self, identity: &Identity, service: &str) -> Result<(), BrokerError> {
        let key = Self::storage_key(identity, service);
        self.store
            .delete(&key)
            .await
            .map_err(|e| BrokerError::Store(e.to_string()))?;
        tracing::info!(
            provider_id = %identity.provider_id,
            external_id = %identity.external_id,
            service = %service,
            "downstream token revoked from vault"
        );
        Ok(())
    }
}
