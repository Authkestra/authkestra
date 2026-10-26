use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

/// Downstream OAuth2/API token managed within the zero-trust token vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DownstreamToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
}

/// Errors arising during downstream token resolution or storage.
#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("token store error: {0}")]
    Store(String),

    #[error("crypto error: {0}")]
    Crypto(#[from] authkestra_crypto_util::CryptoError),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("insufficient scopes for downstream service '{service}': required {required:?}, granted {granted:?}")]
    InsufficientScope {
        service: String,
        required: Vec<String>,
        granted: Vec<String>,
    },

    #[error("downstream token for service '{0}' is expired")]
    TokenExpired(String),
}

/// Zero-trust broker interface for resolving downstream API credentials on behalf of an `Identity`.
#[async_trait]
pub trait DownstreamTokenBroker: Send + Sync + 'static {
    /// Resolves an active downstream API token for `identity` targeting `service` with `scopes`.
    async fn resolve_token(
        &self,
        identity: &Identity,
        service: &str,
        scopes: &[&str],
    ) -> Result<Option<String>, BrokerError>;

    /// Stores an encrypted downstream API token on behalf of `identity`.
    async fn store_token(
        &self,
        identity: &Identity,
        service: &str,
        token: &DownstreamToken,
        ttl: Duration,
    ) -> Result<(), BrokerError>;

    /// Revokes/deletes a stored downstream token.
    async fn revoke_token(&self, identity: &Identity, service: &str) -> Result<(), BrokerError>;
}
