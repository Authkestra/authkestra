use crate::store::{KvStore, StoreError};
use async_trait::async_trait;
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

/// `redis::Client` is a thin, cheaply-`Clone`-able handle (connection info
/// plus lazy connection setup, no open socket of its own), so deriving
/// `Clone` here costs nothing and lets a `RedisStore` be shared across
/// concurrent tasks by value — needed by, e.g., the conformance suite's
/// `insert_if_absent` concurrency test, which spawns many tasks each
/// holding their own clone of the same store.
#[derive(Clone)]
#[non_exhaustive]
pub struct RedisStore {
    client: redis::Client,
    prefix: String,
}

impl RedisStore {
    pub fn new(redis_url: &str, prefix: String) -> Result<Self, StoreError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| StoreError::Internal(format!("Failed to open redis client: {e}")))?;
        tracing::debug!(prefix = %prefix, "Initialized RedisStore");
        Ok(Self { client, prefix })
    }

    /// Create a new `RedisStore` sharing an already-open `redis::Client`.
    ///
    /// This is the preferred constructor when you need multiple stores pointing at the
    /// same Redis instance with different key prefixes — it avoids opening a new TCP
    /// connection per store.
    ///
    /// ```rust,no_run
    /// # use authkestra_engine::store::redis::RedisStore;
    /// let client = redis::Client::open("redis://127.0.0.1/").unwrap();
    /// let sessions  = RedisStore::with_client(client.clone(), "session".into());
    /// let op_codes  = RedisStore::with_client(client.clone(), "op_codes".into());
    /// let op_tokens = RedisStore::with_client(client,          "op_tokens".into());
    /// ```
    pub fn with_client(client: redis::Client, prefix: String) -> Self {
        tracing::debug!(prefix = %prefix, "Initialized RedisStore with shared client");
        Self { client, prefix }
    }

    fn key(&self, id: &str) -> String {
        format!("{prefix}:{id}", prefix = self.prefix)
    }
}

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> KvStore<T> for RedisStore {
    #[tracing::instrument(skip(self))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "loading from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let data: Option<String> = conn.get(self.key(key)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis get error");
            StoreError::Internal(format!("Redis get error: {e}"))
        })?;

        match data {
            Some(json) => {
                let entity: T = serde_json::from_str(&json).map_err(|e| {
                    tracing::error!(error = %e, "Deserialization error");
                    StoreError::Serialization(format!("Deserialization error: {e}"))
                })?;
                Ok(Some(entity))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self, value), fields(key = %key))]
    async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError> {
        tracing::debug!("saving to redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;

        let ttl_secs = ttl.as_secs();
        if ttl_secs == 0 {
            tracing::warn!("ttl is 0, not saving to redis");
            return Ok(());
        }

        let _: () = conn
            .set_ex(self.key(key), json, ttl_secs)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis set error");
                StoreError::Internal(format!("Redis set error: {e}"))
            })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!(key = %key, "deleting from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let _: () = conn.del(self.key(key)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis del error");
            StoreError::Internal(format!("Redis del error: {e}"))
        })?;

        Ok(())
    }
}

use crate::store::{ttl_ceil_secs, AtomicConsume, AtomicDecrement, AtomicInsert, IndexedKvStore};

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicInsert<T> for RedisStore {
    #[tracing::instrument(skip(self, value))]
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        tracing::debug!(key = %key, "atomically inserting into redis store if absent");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;

        // Redis' `EX` only accepts whole seconds — see `ttl_ceil_secs` for
        // why this must round up, not truncate.
        let ttl_secs = ttl_ceil_secs(ttl);

        // `SET key value NX EX ttl` — a single atomic Redis command. Redis
        // replies `+OK` (parsed by this crate as `Value::Okay`, which
        // `bool`'s `FromRedisValue` maps to `true`) on a fresh insert, or
        // nil (maps to `false`) when the key already existed and NX blocked
        // the write — exactly the replay-vs-fresh signal this trait needs.
        let options = redis::SetOptions::default()
            .conditional_set(redis::ExistenceCheck::NX)
            .with_expiration(redis::SetExpiry::EX(ttl_secs));

        let inserted: bool = conn
            .set_options(self.key(key), json, options)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis set_options (NX) error");
                StoreError::Internal(format!("Redis set_options (NX) error: {e}"))
            })?;

        Ok(inserted)
    }
}

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicConsume<T> for RedisStore {
    #[tracing::instrument(skip(self))]
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(key = %key, "atomically consuming from redis store");

        // Note: We atomically consume the primary key using a Lua script.
        // The associated index_key (if any) is not deleted here because it is not provided
        // to `consume()`. This is benign: the stale index will expire simultaneously
        // via its matching TTL, and `get_by_index` gracefully cleans up any orphaned pointers.
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let script = redis::Script::new(
            r#"
            local val = redis.call('GET', KEYS[1])
            if val then
                redis.call('DEL', KEYS[1])
            end
            return val
            "#,
        );

        let data: Option<String> = script
            .key(self.key(key))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis get/del script error");
                StoreError::Internal(format!("Redis get/del script error: {e}"))
            })?;

        match data {
            Some(json) => {
                let entity: T = serde_json::from_str(&json).map_err(|e| {
                    tracing::error!(error = %e, "Deserialization error");
                    StoreError::Serialization(format!("Deserialization error: {e}"))
                })?;
                Ok(Some(entity))
            }
            None => Ok(None),
        }
    }
}

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> AtomicDecrement<T> for RedisStore {
    #[tracing::instrument(skip(self))]
    async fn init_counter(&self, key: &str, value: u32, ttl: Duration) -> Result<(), StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        // Whole seconds only, rounded up — same reasoning as every other
        // TTL here; see `ttl_ceil_secs`.
        let ttl_secs = ttl_ceil_secs(ttl);
        let _: () = conn
            .set_ex(self.counter_key(key), value, ttl_secs)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis counter init error");
                StoreError::Internal(format!("Redis counter init error: {e}"))
            })?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn decrement(&self, key: &str) -> Result<Option<u32>, StoreError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        // A script rather than a bare `DECR` for two reasons: `DECR` on a
        // missing key creates it at -1, which would turn an expired counter
        // into an unlimited one, and it has no floor, so a spent counter
        // would run negative. Both are handled here inside the same atomic
        // evaluation, so no caller can observe a value between the read and
        // the write.
        //
        // An exhausted counter returns nil, not 0 — the contract requires
        // "already spent" to be distinguishable from "took the last attempt",
        // so a count is only ever returned for an attempt actually granted.
        let script = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return nil
            end
            local n = tonumber(current)
            if n <= 0 then
                return nil
            end
            return redis.call('DECR', KEYS[1])
            "#,
        );

        let remaining: Option<i64> = script
            .key(self.counter_key(key))
            .invoke_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis decrement script error");
                StoreError::Internal(format!("Redis decrement script error: {e}"))
            })?;

        // The script floors at zero, so a negative value here would mean the
        // key was written by something other than `init_counter`. Clamping
        // rather than trusting it keeps a malformed counter from reading as
        // an enormous budget once it is cast to `u32`.
        Ok(remaining.map(|n| n.max(0) as u32))
    }
}

impl RedisStore {
    /// Where the retry budget for `key` lives.
    ///
    /// A sibling key rather than a field inside the stored value, so the
    /// decrement is a plain integer operation Redis can do atomically. See
    /// [`AtomicDecrement`].
    fn counter_key(&self, id: &str) -> String {
        format!("{prefix}:ctr:{id}", prefix = self.prefix)
    }

    fn index_key(&self, index: &str) -> String {
        format!("{prefix}:idx:{index}", prefix = self.prefix)
    }
}

#[async_trait]
impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> IndexedKvStore<T> for RedisStore {
    #[tracing::instrument(skip(self, value), fields(key = %key, index = %index))]
    async fn set_indexed(
        &self,
        key: &str,
        index: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed to redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;

        let ttl_secs = ttl.as_secs();
        if ttl_secs == 0 {
            tracing::warn!("ttl is 0, not saving to redis");
            return Ok(());
        }

        let mut pipe = redis::pipe();
        pipe.atomic().set_ex(self.key(key), json, ttl_secs).set_ex(
            self.index_key(index),
            key.to_string(),
            ttl_secs,
        );

        let _: () = pipe.query_async(&mut conn).await.map_err(|e| {
            tracing::error!(error = %e, "Redis set_indexed error");
            StoreError::Internal(format!("Redis set_indexed error: {e}"))
        })?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_index(&self, index: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!(index = %index, "loading by index from redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let rel_key: Option<String> = conn.get(self.index_key(index)).await.map_err(|e| {
            tracing::error!(error = %e, "Redis index get error");
            StoreError::Internal(format!("Redis index get error: {e}"))
        })?;

        if let Some(key) = rel_key {
            let res = self.get(&key).await;
            if let Ok(None) = res {
                // Orphaned index, clean it up optionally
                let _: () = conn.del(self.index_key(index)).await.unwrap_or(());
            }
            res
        } else {
            Ok(None)
        }
    }

    #[tracing::instrument(skip(self, value, predicate), fields(key = %key, index = %index))]
    async fn update_indexed_if(
        &self,
        key: &str,
        index: &str,
        value: T,
        ttl: Duration,
        predicate: for<'a> fn(&'a T) -> bool,
    ) -> Result<bool, StoreError> {
        tracing::debug!("conditionally updating indexed record in redis store");
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Redis connection error");
                StoreError::Internal(format!("Redis connection error: {e}"))
            })?;

        let new_json = serde_json::to_string(&value).map_err(|e| {
            tracing::error!(error = %e, "Serialization error");
            StoreError::Serialization(format!("Serialization error: {e}"))
        })?;

        let ttl_secs = ttl.as_secs().max(1);
        let primary_redis_key = self.key(key);
        let index_redis_key = self.index_key(index);

        let script = redis::Script::new(
            r#"
            local current = redis.call('GET', KEYS[1])
            if not current then
                return -1
            end
            if current ~= ARGV[1] then
                return 0
            end
            redis.call('SETEX', KEYS[1], tonumber(ARGV[3]), ARGV[2])
            redis.call('SETEX', KEYS[2], tonumber(ARGV[3]), ARGV[4])
            return 1
            "#,
        );

        for _ in 0..4 {
            let current_json: Option<String> = conn.get(&primary_redis_key).await.map_err(|e| {
                tracing::error!(error = %e, "Redis get error in update_indexed_if");
                StoreError::Internal(format!("Redis get error: {e}"))
            })?;

            let Some(current_json) = current_json else {
                return Ok(false);
            };

            let current_val: T = serde_json::from_str(&current_json).map_err(|e| {
                tracing::error!(error = %e, "Deserialization error in update_indexed_if");
                StoreError::Serialization(format!("Deserialization error: {e}"))
            })?;

            if !predicate(&current_val) {
                return Ok(false);
            }

            let status: i32 = script
                .key(&primary_redis_key)
                .key(&index_redis_key)
                .arg(&current_json)
                .arg(&new_json)
                .arg(ttl_secs)
                .arg(key)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Redis update_indexed_if script error");
                    StoreError::Internal(format!("Redis update_indexed_if script error: {e}"))
                })?;

            match status {
                1 => return Ok(true),
                -1 => return Ok(false),
                _ => continue,
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{AtomicConsume, IndexedKvStore, KvStore};
    use std::time::Duration;
    use testcontainers::{runners::AsyncRunner, ContainerAsync};
    use testcontainers_modules::redis::Redis;

    async fn setup_redis() -> (RedisStore, ContainerAsync<Redis>) {
        let container = Redis::default().start().await.unwrap();
        let port = container.get_host_port_ipv4(6379).await.unwrap();
        let url = format!("redis://127.0.0.1:{}", port);

        let store = RedisStore::new(&url, "test_prefix".to_string()).unwrap();
        (store, container)
    }

    #[tokio::test]
    async fn test_redis_get_set_delete() {
        let (store, _c) = setup_redis().await;

        let res: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res, None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let res_some: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res_some, Some("value1".to_string()));

        KvStore::<String>::delete(&store, "key1").await.unwrap();
        let res_del: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(res_del, None);
    }

    #[tokio::test]
    async fn test_redis_atomic_consume() {
        let (store, _c) = setup_redis().await;

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let val: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));

        let val2: Option<String> = store.consume("key1").await.unwrap();
        assert_eq!(val2, None);
    }

    #[tokio::test]
    async fn test_redis_insert_if_absent() {
        let (store, _c) = setup_redis().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted);

        // A second insert under the same key — the replay case — must be
        // rejected, and must not clobber the value the first insert wrote.
        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!inserted_again);

        let val: Option<String> = store.get("key1").await.unwrap();
        assert_eq!(val, Some("value1".to_string()));
    }

    /// Regression test: a sub-second TTL must not silently disable the
    /// replay guard. Before the fix, `ttl.as_secs()` truncated any
    /// sub-second duration to 0, which hit an early-return path that
    /// reported `Ok(true)` ("fresh") without ever calling Redis — so a
    /// second `insert_if_absent` for the *same* key also found nothing
    /// stored and *also* reported `Ok(true)`, meaning a replayed key was
    /// never detected as long as its TTL was under a second.
    #[tokio::test]
    async fn test_redis_insert_if_absent_with_sub_second_ttl_still_blocks_a_replay() {
        let (store, _c) = setup_redis().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(10))
            .await
            .unwrap();
        assert!(inserted, "the first insert must succeed");

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_millis(10))
            .await
            .unwrap();
        assert!(
            !inserted_again,
            "a second insert under the same key, even with a sub-second TTL, is a replay and must be rejected"
        );
    }

    /// Same property at exactly `Duration::ZERO`, the most extreme case of
    /// the same bug.
    #[tokio::test]
    async fn test_redis_insert_if_absent_with_zero_ttl_still_blocks_a_replay() {
        let (store, _c) = setup_redis().await;

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::ZERO)
            .await
            .unwrap();
        assert!(inserted, "the first insert must succeed");

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::ZERO)
            .await
            .unwrap();
        assert!(!inserted_again, "a zero-TTL replay must still be rejected");
    }

    /// Regression test for authkestra#277's review: a fractional-second TTL
    /// must round *up*, not truncate down — `.as_secs()` alone would floor
    /// 1.5s to 1s, silently shortening the replay window below what the
    /// caller asked for on every call with a sub-second remainder, not just
    /// the exact-zero case the other two tests above cover.
    #[tokio::test]
    async fn test_redis_insert_if_absent_rounds_a_fractional_ttl_up() {
        let (store, _c) = setup_redis().await;

        store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_millis(1500))
            .await
            .unwrap();

        let mut conn = store
            .client
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let ttl: i64 = redis::AsyncCommands::ttl(&mut conn, store.key("key1"))
            .await
            .unwrap();
        assert_eq!(ttl, 2, "a 1.5s TTL must round up to 2s, not truncate to 1s");
    }

    #[tokio::test]
    async fn test_redis_indexed_store() {
        let (store, _c) = setup_redis().await;

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        let pk_res: Option<String> = store.get("pk1").await.unwrap();
        assert_eq!(pk_res, Some("value1".to_string()));

        let sk_res: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res, Some("value1".to_string()));

        // Delete primary key manually
        KvStore::<String>::delete(&store, "pk1").await.unwrap();

        // This should return None and clean up the orphaned index
        let sk_res2: Option<String> = store.get_by_index("sk1").await.unwrap();
        assert_eq!(sk_res2, None);
    }
}
