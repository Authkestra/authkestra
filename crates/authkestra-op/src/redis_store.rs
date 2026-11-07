use crate::client_assertion::ClientAssertionStore;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;

/// A Redis-backed store for client assertions to prevent replay attacks.
#[derive(Clone)]
#[non_exhaustive]
pub struct RedisClientAssertionStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisClientAssertionStore {
    /// Creates a new RedisClientAssertionStore from a redis URL and a key prefix.
    pub async fn new(
        redis_url: &str,
        prefix: String,
    ) -> Result<Self, authkestra_engine::store::StoreError> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            tracing::error!(error = %e, "Failed to open redis client");
            authkestra_engine::store::StoreError::Internal("redis".into())
        })?;
        Self::with_client(client, prefix).await
    }

    /// Creates a new RedisClientAssertionStore from an existing redis client and a key prefix.
    pub async fn with_client(
        client: redis::Client,
        prefix: String,
    ) -> Result<Self, authkestra_engine::store::StoreError> {
        let conn = client.get_connection_manager().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to create Redis connection manager");
            authkestra_engine::store::StoreError::Internal("redis".into())
        })?;
        Ok(Self::with_connection_manager(conn, prefix))
    }

    /// Creates a new RedisClientAssertionStore from a pre-configured `ConnectionManager`.
    pub fn with_connection_manager(conn: ConnectionManager, prefix: String) -> Self {
        Self { conn, prefix }
    }

    fn key(&self, jti: &str) -> String {
        format!("{prefix}:{jti}", prefix = self.prefix)
    }
}

#[async_trait]
impl ClientAssertionStore for RedisClientAssertionStore {
    async fn record_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        let now = Utc::now();
        let diff = expires_at - now;
        let ttl_ms = diff.num_milliseconds();
        if ttl_ms <= 0 {
            tracing::debug!(jti = %jti, "Assertion is already expired; refusing without querying Redis");
            return Ok(false);
        }
        let ttl_secs = (ttl_ms as u64).div_ceil(1000).max(1);

        let mut conn = self.conn.clone();
        let res: Option<String> = redis::cmd("SET")
            .arg(self.key(jti))
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis SET NX error");
                authkestra_engine::store::StoreError::Internal("redis".into())
            })?;

        // If res is Some("OK"), it means SET NX succeeded (the JTI is new).
        Ok(res.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::redis::REDIS_PORT;

    #[tokio::test]
    async fn test_redis_client_assertion_store_replay_protection() {
        let node = testcontainers_modules::redis::Redis::default()
            .start()
            .await
            .unwrap();
        let host_port = node.get_host_port_ipv4(REDIS_PORT).await.unwrap();
        let redis_url = format!("redis://127.0.0.1:{host_port}");

        let mut store = RedisClientAssertionStore::new(&redis_url, "test_jti".to_string())
            .await
            .unwrap();

        let exp = Utc::now() + chrono::Duration::seconds(60);

        // 1. First record_jti succeeds (returns true)
        let first = store.record_jti("unique-jti-1", exp).await.unwrap();
        assert!(first, "First presentation of JTI must succeed");

        // 2. Second record_jti before expiration fails (returns false - replay prevented)
        let second = store.record_jti("unique-jti-1", exp).await.unwrap();
        assert!(!second, "Replay of same JTI must be rejected");

        // 3. Different JTI succeeds
        let another = store.record_jti("unique-jti-2", exp).await.unwrap();
        assert!(another, "Different JTI must succeed");

        // 4. Expired timestamp returns false immediately
        let past = Utc::now() - chrono::Duration::seconds(10);
        let expired = store.record_jti("unique-jti-3", past).await.unwrap();
        assert!(
            !expired,
            "Already-expired assertion must be rejected immediately"
        );

        // 5. Fractional second TTL (1500ms) rounds upward to 2s, preventing premature expiry
        let fractional_exp = Utc::now() + chrono::Duration::milliseconds(1500);
        let recorded = store
            .record_jti("fractional-jti", fractional_exp)
            .await
            .unwrap();
        assert!(
            recorded,
            "Initial registration with fractional TTL must succeed"
        );
        // Verify key exists in Redis with PTTL > 1000ms (proving rounding up to 2s rather than truncating to 1s)
        let mut conn = store.conn.clone();
        let pttl: i64 = redis::cmd("PTTL")
            .arg(store.key("fractional-jti"))
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(
            pttl > 1000,
            "Replay marker PTTL ({pttl}ms) must exceed 1000ms so a 1500ms window is rounded up to 2s"
        );
    }
}
