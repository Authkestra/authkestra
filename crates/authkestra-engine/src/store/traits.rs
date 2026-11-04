use crate::oauth2::client::ClientRegistration;
use crate::oauth2::code::AuthorizationCode;
use crate::oauth2::device::{DeviceCodeSession, DeviceCodeStatus};
use crate::oauth2::refresh::RefreshToken;
use crate::store::StoreError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError>;
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError>;
    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError>;
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError>;
    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError>;
    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError>;
    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError>;
}

#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError>;
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError>;
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError>;
    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError>;
    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError>;
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError>;
}

#[async_trait]
pub trait ClientAssertionStore: Send + Sync {
    async fn record_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
}

#[async_trait]
pub trait DpopReplayStore: Send + Sync {
    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
}

/// The exact `StoreError::Internal` payload [`NoClientAssertionStore`]
/// fails with — `authkestra_op::error::OpError`'s `From<StoreError>` impl
/// matches on this literal to recover the distinct
/// `OpError::ReplayProtectionUnavailable` variant instead of collapsing it
/// into the generic `OpError::Storage`. A `pub const` rather than two
/// independent string literals so the two crates can't drift apart.
pub const CLIENT_ASSERTION_REPLAY_PROTECTION_UNAVAILABLE: &str =
    "ClientAssertionReplayProtectionUnavailable";

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NoClientAssertionStore;
#[async_trait]
impl ClientAssertionStore for NoClientAssertionStore {
    async fn record_jti(
        &mut self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        // A hard `Err`, not `Ok(false)` — same shape as `NoDpopReplayStore`
        // below, and for the same reason: `Ok(false)` reads identically to
        // an actual replay to anything downstream that only checks the
        // bool, so a deployment with `private_key_jwt` enabled but no real
        // `ClientAssertionStore` wired would have every legitimate request
        // logged as "already been spent — replay refused" alongside this
        // warning, muddying exactly the misconfiguration-vs-attack
        // distinction this log line exists to preserve.
        tracing::warn!(
            "a private_key_jwt client assertion was presented but no ClientAssertionStore \
             is wired; refusing it (this looks identical to a replay to the caller, but is \
             a missing-store misconfiguration)"
        );
        Err(StoreError::Internal(
            CLIENT_ASSERTION_REPLAY_PROTECTION_UNAVAILABLE.into(),
        ))
    }
}

use crate::store::{AtomicConsume, AtomicInsert, IndexedKvStore, KvStore};

#[async_trait]
impl<S> ClientStore for S
where
    S: KvStore<ClientRegistration> + Send + Sync,
{
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        self.get(client_id).await
    }
}

#[async_trait]
impl<S> AuthorizationCodeStore for S
where
    S: KvStore<AuthorizationCode> + AtomicConsume<AuthorizationCode> + Send + Sync,
{
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        let ttl = code
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(0));
        self.set(&code.code.clone(), code, ttl).await
    }

    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        self.consume(code).await
    }
}

#[async_trait]
impl<S> RefreshTokenStore for S
where
    S: KvStore<RefreshToken> + AtomicConsume<RefreshToken> + Send + Sync,
{
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        let ttl = token
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(0));
        self.set(&token.token.clone(), token, ttl).await
    }

    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        self.get(token).await
    }

    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        self.delete(token).await
    }

    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        self.consume(token).await
    }
}

/// How long past `expires_at` a device code session's storage row stays
/// alive. Keeping it around for 5 minutes after expiry lets the token
/// endpoint's own expiry check find the row and return `expired_token`
/// (RFC 8628 §3.5) instead of `invalid_grant` — a TTL that expired exactly
/// at `expires_at` would already have evicted the row by the time that
/// check runs. Extracted so the grace period itself has a direct unit test
/// rather than only being exercised incidentally by handler-level tests.
fn device_code_ttl(expires_at: DateTime<Utc>) -> std::time::Duration {
    expires_at
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(0))
        + std::time::Duration::from_secs(300)
}

#[async_trait]
impl<S> DeviceCodeStore for S
where
    S: IndexedKvStore<DeviceCodeSession> + AtomicConsume<DeviceCodeSession> + Send + Sync,
{
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let ttl = device_code_ttl(session.expires_at);
        self.set_indexed(
            &session.device_code.clone(),
            &session.user_code.clone(),
            session,
            ttl,
        )
        .await
    }

    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        self.get(device_code).await
    }

    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        self.get_by_index(user_code).await
    }

    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let current = self.get_device_code(&session.device_code).await?;
        match current {
            Some(existing) if matches!(existing.status, DeviceCodeStatus::Pending) => {
                let ttl = device_code_ttl(session.expires_at);
                self.set_indexed(
                    &session.device_code.clone(),
                    &session.user_code.clone(),
                    session,
                    ttl,
                )
                .await
            }
            Some(_) => {
                tracing::warn!(
                    device_code = %session.device_code,
                    "update_device_code rejected: session is no longer in Pending state"
                );
                Err(StoreError::NotFound)
            }
            None => {
                tracing::warn!(
                    device_code = %session.device_code,
                    "update_device_code rejected: session not found"
                );
                Err(StoreError::NotFound)
            }
        }
    }

    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        self.delete(device_code).await
    }

    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        self.consume(device_code).await
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct DpopJtiRecord {
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}

impl DpopJtiRecord {
    pub fn new(jti: String, expires_at: DateTime<Utc>) -> Self {
        Self { jti, expires_at }
    }
}

/// Same purpose as [`CLIENT_ASSERTION_REPLAY_PROTECTION_UNAVAILABLE`], for
/// [`NoDpopReplayStore`]'s sibling `OpError::DpopReplayProtectionUnavailable`.
pub const DPOP_REPLAY_PROTECTION_UNAVAILABLE: &str = "DpopReplayProtectionUnavailable";

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NoDpopReplayStore;
#[async_trait]
impl DpopReplayStore for NoDpopReplayStore {
    async fn check_and_record_dpop_jti(
        &mut self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        tracing::error!("a DPoP proof was presented but no DpopReplayStore is wired; refusing it rather than accepting a proof that could be replayed");
        Err(StoreError::Internal(
            DPOP_REPLAY_PROTECTION_UNAVAILABLE.into(),
        ))
    }
}

#[async_trait]
impl<S> DpopReplayStore for S
where
    S: KvStore<DpopJtiRecord> + AtomicInsert<DpopJtiRecord> + Send + Sync,
{
    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        tracing::trace!("attempting to record dpop proof jti");
        let ttl = expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(0));

        self.insert_if_absent(jti, DpopJtiRecord::new(jti.to_string(), expires_at), ttl)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Regression test for a device code session's post-expiry grace
    /// window: a handler-level test can pass on an accidentally-short TTL
    /// simply because it looks the row up microseconds after storing it
    /// (see `authkestra-op`'s device-flow tests). This pins the actual
    /// duration instead.
    #[test]
    fn device_code_ttl_keeps_an_already_expired_session_for_five_more_minutes() {
        let expires_at = Utc::now() - Duration::hours(1);
        let ttl = device_code_ttl(expires_at);
        assert!(
            ttl >= std::time::Duration::from_secs(299) && ttl <= std::time::Duration::from_secs(301),
            "an already-expired device code must be kept for ~5 more minutes \
             (RFC 8628 §3.5's expired_token vs invalid_grant distinction depends on it), got {ttl:?}"
        );
    }

    #[test]
    fn device_code_ttl_adds_the_grace_period_on_top_of_remaining_time() {
        let expires_at = Utc::now() + Duration::minutes(10);
        let ttl = device_code_ttl(expires_at);
        // ~10 minutes remaining + 5 minutes grace, with a few seconds of
        // slack for the test's own execution time.
        assert!(
            ttl >= std::time::Duration::from_secs(14 * 60)
                && ttl <= std::time::Duration::from_secs(16 * 60),
            "grace period must extend, not replace, the remaining validity window, got {ttl:?}"
        );
    }
}
