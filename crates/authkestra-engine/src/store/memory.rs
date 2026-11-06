use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::store::{
    ttl_ceil_secs, AtomicConsume, AtomicDecrement, AtomicInsert, IndexedKvStore, KvStore,
    StoreError,
};
use async_trait::async_trait;

struct StoreEntry<T> {
    value: T,
    expires_at: Option<Instant>,
}

/// A min-heap of (expiry, key) pairs, oldest first — see
/// `MemoryStore::insert_if_absent` for why it exists and how it's used.
type ExpiryQueue = BinaryHeap<Reverse<(Instant, String)>>;

impl<T> StoreEntry<T> {
    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() >= expires_at
        } else {
            false
        }
    }
}

/// An in-memory implementation of [`KvStore`].
///
/// **Note**: This store is not persistent and will be cleared when the application restarts.
/// It is primarily intended for development and testing.
#[derive(Clone)]
#[non_exhaustive]
pub struct MemoryStore<T> {
    data: Arc<Mutex<HashMap<String, StoreEntry<T>>>>,
    indices: Arc<Mutex<HashMap<String, String>>>,
    /// Expiry order for entries written through `insert_if_absent` — see
    /// that method for why this exists and how it's used.
    insert_only_expiry_queue: Arc<Mutex<ExpiryQueue>>,
    /// Retry budgets, kept apart from `data` because they are bare integers
    /// rather than `T` — see [`AtomicDecrement`]. Reuses `StoreEntry` for its
    /// expiry handling rather than repeating it.
    counters: Arc<Mutex<HashMap<String, StoreEntry<u32>>>>,
}

impl<T> Default for MemoryStore<T> {
    fn default() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            indices: Arc::new(Mutex::new(HashMap::new())),
            insert_only_expiry_queue: Arc::new(Mutex::new(BinaryHeap::new())),
            counters: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<T> MemoryStore<T> {
    /// Create a new, empty `MemoryStore`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<T> MemoryStore<T> {
    /// Test-only introspection: the number of entries currently held,
    /// expired or not. Used to prove `insert_if_absent`'s opportunistic
    /// sweep actually shrinks the map, not just that expired entries are
    /// unreachable through the public API.
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> KvStore<T> for MemoryStore<T> {
    #[tracing::instrument(skip(self, key))]
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!("loading from memory store");
        let mut data = self
            .data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?;

        if let Some(entry) = data.get(key) {
            if entry.is_expired() {
                data.remove(key);
                return Ok(None);
            }
            return Ok(Some(entry.value.clone()));
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self, key, value))]
    async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError> {
        tracing::debug!("saving to memory store");
        let entry = StoreEntry {
            value,
            expires_at: Some(Instant::now() + ttl),
        };
        self.data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?
            .insert(key.to_string(), entry);
        Ok(())
    }

    #[tracing::instrument(skip(self, key))]
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        tracing::debug!("deleting from memory store");
        self.data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?
            .remove(key);
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + serde::Serialize + Send + Sync + 'static> AtomicConsume<T> for MemoryStore<T> {
    /// Atomically fetches and removes the value stored under `key`.
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!("atomically consuming from memory store");
        let mut data = self
            .data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?;
        if let Some(entry) = data.remove(key) {
            if entry.is_expired() {
                return Ok(None);
            }
            return Ok(Some(entry.value));
        }
        Ok(None)
    }

    /// Atomically deletes the entry at `key` only if its unexpired value equals `expected`.
    async fn delete_if_eq(&self, key: &str, expected: &T) -> Result<bool, StoreError> {
        tracing::debug!(key = %key, "atomically deleting if equal from memory store");
        let expected_val =
            serde_json::to_value(expected).map_err(|e| StoreError::Serialization(e.to_string()))?;
        let mut data = self
            .data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?;
        if let Some(entry) = data.get(key) {
            if entry.is_expired() {
                data.remove(key);
                return Ok(false);
            }
            let current_val = serde_json::to_value(&entry.value)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            if current_val == expected_val {
                data.remove(key);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> AtomicDecrement<T> for MemoryStore<T> {
    async fn init_counter(&self, key: &str, value: u32, ttl: Duration) -> Result<(), StoreError> {
        tracing::debug!(value, "initialising a counter in memory store");
        let mut counters = self.counters.lock().unwrap();
        // Opportunistic sweep, in the same spirit as `insert_if_absent`'s.
        // A counter is only ever reclaimed by a later `decrement` on its own
        // key, so a challenge that is minted and then abandoned — the common
        // case, since most codes are simply never submitted — would otherwise
        // leak an entry for the life of the process.
        counters.retain(|_, entry| !entry.is_expired());
        counters.insert(
            key.to_string(),
            StoreEntry {
                value,
                expires_at: Some(Instant::now() + ttl),
            },
        );
        Ok(())
    }

    async fn decrement(&self, key: &str) -> Result<Option<u32>, StoreError> {
        // The whole operation runs under one lock, which is what makes it
        // atomic: two callers cannot both observe the pre-decrement value.
        let mut counters = self.counters.lock().unwrap();
        let Some(entry) = counters.get_mut(key) else {
            tracing::debug!("no counter to decrement");
            return Ok(None);
        };
        if entry.is_expired() {
            counters.remove(key);
            tracing::debug!("counter had expired");
            return Ok(None);
        }
        if entry.value == 0 {
            // Already spent. Reported as "no attempt available" rather than
            // `Some(0)`, so a caller can tell an authorised last attempt from
            // one that was never granted.
            tracing::debug!("counter already spent");
            return Ok(None);
        }
        entry.value -= 1;
        let remaining = entry.value;
        tracing::debug!(remaining, "decremented a counter");
        Ok(Some(remaining))
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> AtomicInsert<T> for MemoryStore<T> {
    #[tracing::instrument(skip(self, key, value))]
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError> {
        tracing::debug!("atomically inserting into memory store if absent");
        // Held for the whole check-then-insert: this single lock is what
        // makes the operation atomic, exactly like `consume`'s single
        // `remove` call above.
        let mut data = self
            .data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?;
        let mut expiry_queue = self.insert_only_expiry_queue.lock().unwrap();

        // `get`/`consume` each self-heal by removing an expired entry the
        // next time *that same key* is looked up — but `insert_if_absent`
        // is also used for insert-only key spaces (a DPoP proof's `jti`,
        // unique per proof) where no later call ever revisits the same
        // key. Without reclaiming these separately, such an entry would
        // sit expired-but-present forever: nothing else would ever touch
        // its key to trigger removal, leaking one entry per call for the
        // life of the process.
        //
        // `insert_only_expiry_queue` tracks exactly this key space, ordered
        // by expiry. Popping while the earliest entry has expired costs
        // O(log n) per popped item, and each item is pushed once and
        // popped at most once — so the amortized cost per call is
        // O(log n), not the O(n) a full-map scan on every call would be
        // (which, at R requests/sec against a T-second TTL, is quadratic
        // in R: each of the ~R*T live entries gets rescanned on every one
        // of the R calls per second).
        //
        // A popped entry is discarded as a no-op, not removed from `data`,
        // if `data` no longer holds it under the exact expiry this queue
        // entry was pushed for — that happens when the same key was later
        // reinserted with a new TTL after this entry was queued, which
        // pushed its own, newer queue entry for the same key. Without this
        // guard a stale queue entry could wrongly evict a key's *current*
        // value.
        let now = Instant::now();
        while let Some(Reverse((expiry, _))) = expiry_queue.peek() {
            if *expiry > now {
                break;
            }
            let Reverse((expiry, stale_key)) = expiry_queue.pop().unwrap();
            if data
                .get(&stale_key)
                .is_some_and(|entry| entry.expires_at == Some(expiry))
            {
                data.remove(&stale_key);
            }
        }

        if let Some(entry) = data.get(key) {
            // Only reachable for a key written through some path other
            // than `insert_if_absent` (e.g. `set`) that the queue above
            // doesn't track — the sweep already handled everything in
            // this key space.
            if !entry.is_expired() {
                return Ok(false);
            }
        }

        // A sub-second (or zero/negative-effective) `ttl` must not shrink
        // to nothing: `insert_if_absent`'s `Ok`/`Err` is a security-critical
        // replay signal (see `ttl_ceil_secs`'s own doc comment — this is
        // the same bug, independently reachable here since this backend
        // never called it before). Concretely: a `jti`/`expires_at` pair
        // whose duration-until-expiry rounds to zero (e.g.
        // `check_and_record_dpop_jti` clamping an already-elapsed or
        // exactly-now `expires_at` to `Duration::ZERO`) would insert an
        // entry that is already expired the instant it's checked; the very
        // next presentation of the *same* key would then have this
        // opportunistic sweep reclaim it as stale before the "already
        // present" check below ever runs, and be accepted as fresh —
        // silently defeating the replay guard for exactly the proofs
        // closest to their own freshness-window boundary. Flooring to
        // whole seconds costs nothing here (this store already only
        // guarantees second-scale scheduling via `Instant`), and keeps
        // this backend's floor identical to every other `AtomicInsert`
        // backend's.
        let ttl = Duration::from_secs(ttl_ceil_secs(ttl));
        let expires_at = now + ttl;
        data.insert(
            key.to_string(),
            StoreEntry {
                value,
                expires_at: Some(expires_at),
            },
        );
        expiry_queue.push(Reverse((expires_at, key.to_string())));
        Ok(true)
    }
}

#[async_trait]
impl<T: Clone + Send + Sync + 'static> IndexedKvStore<T> for MemoryStore<T> {
    async fn set_indexed(
        &self,
        primary_key: &str,
        secondary_key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        tracing::debug!("saving indexed record to memory store");
        let entry = StoreEntry {
            value,
            expires_at: Some(Instant::now() + ttl),
        };
        let mut data = self
            .data
            .lock()
            .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?;
        let mut indices = self.indices.lock().unwrap();

        data.insert(primary_key.to_string(), entry);
        indices.insert(secondary_key.to_string(), primary_key.to_string());

        Ok(())
    }

    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<T>, StoreError> {
        tracing::debug!("loading by index from memory store");
        let primary_key_opt = {
            let indices = self.indices.lock().unwrap();
            indices.get(secondary_key).cloned()
        };

        if let Some(primary_key) = primary_key_opt {
            let mut data = self
                .data
                .lock()
                .map_err(|e| StoreError::Internal(format!("mutex poisoned: {e}")))?;
            if let Some(entry) = data.get(&primary_key) {
                if entry.is_expired() {
                    data.remove(&primary_key);
                    // Also cleanup index opportunistically
                    self.indices.lock().unwrap().remove(secondary_key);
                    return Ok(None);
                }
                return Ok(Some(entry.value.clone()));
            } else {
                // Orphaned index pointer cleanup
                self.indices.lock().unwrap().remove(secondary_key);
            }
        }
        Ok(None)
    }
}

/// An in-memory implementation of [`crate::auth::CredentialStore`].
#[cfg(any(feature = "webauthn", feature = "totp", feature = "recovery-codes"))]
#[derive(Clone, Default, Debug)]
pub struct MemoryCredentialStore {
    creds: Arc<Mutex<HashMap<String, Vec<serde_json::Value>>>>,
}

#[cfg(any(feature = "webauthn", feature = "totp", feature = "recovery-codes"))]
impl MemoryCredentialStore {
    /// Create a new empty `MemoryCredentialStore`.
    pub fn new() -> Self {
        Self {
            creds: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Acquires the internal credential mutex, mapping a poisoned lock to `AuthError::Internal`.
    fn lock(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<String, Vec<serde_json::Value>>>,
        crate::auth::error::AuthError,
    > {
        self.creds.lock().map_err(|_| {
            tracing::error!("memory credential store mutex poisoned");
            crate::auth::error::AuthError::Internal("credential store unavailable".into())
        })
    }
}

#[cfg(any(feature = "webauthn", feature = "totp", feature = "recovery-codes"))]
#[async_trait]
impl crate::auth::CredentialStore for MemoryCredentialStore {
    /// Saves or replaces a credential for `user_id` and `cred_type`.
    async fn save_credential(
        &self,
        user_id: &str,
        cred_type: &str,
        data: serde_json::Value,
    ) -> Result<(), crate::auth::error::AuthError> {
        let key = format!("{user_id}:{cred_type}");
        let mut creds = self.lock()?;
        let list = creds.entry(key).or_default();
        let cred_id = data
            .get("credential_id")
            .or_else(|| data.get("id"))
            .and_then(|v| v.as_str());
        if let Some(id) = cred_id {
            if let Some(pos) = list.iter().position(|c| {
                c.get("credential_id")
                    .or_else(|| c.get("id"))
                    .and_then(|v| v.as_str())
                    == Some(id)
            }) {
                list[pos] = data;
                return Ok(());
            }
        }
        list.push(data);
        Ok(())
    }

    /// Retrieves all credentials stored for `user_id` and `cred_type`.
    async fn get_credentials(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> Result<Vec<serde_json::Value>, crate::auth::error::AuthError> {
        let key = format!("{user_id}:{cred_type}");
        let creds = self.lock()?;
        Ok(creds.get(&key).cloned().unwrap_or_default())
    }

    /// Updates fields of a stored credential identified by `credential_id`.
    async fn update_credential(
        &self,
        credential_id: &str,
        data: serde_json::Value,
    ) -> Result<(), crate::auth::error::AuthError> {
        let mut creds = self.lock()?;
        for list in creds.values_mut() {
            for val in list.iter_mut() {
                if let Some(obj) = val.as_object_mut() {
                    if obj
                        .get("credential_id")
                        .or_else(|| obj.get("id"))
                        .and_then(|v| v.as_str())
                        == Some(credential_id)
                    {
                        if let Some(update_obj) = data.as_object() {
                            for (k, v) in update_obj {
                                obj.insert(k.clone(), v.clone());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Deletes a specific credential by `credential_id` for `user_id` and `cred_type`.
    async fn delete_credential(
        &self,
        user_id: &str,
        cred_type: &str,
        credential_id: &str,
    ) -> Result<bool, crate::auth::error::AuthError> {
        let key = format!("{user_id}:{cred_type}");
        let mut creds = self.lock()?;
        if let Some(list) = creds.get_mut(&key) {
            let orig = list.len();
            list.retain(|c| {
                c.get("credential_id")
                    .or_else(|| c.get("id"))
                    .and_then(|v| v.as_str())
                    != Some(credential_id)
            });
            Ok(list.len() < orig)
        } else {
            Ok(false)
        }
    }

    /// Deletes all credentials of `cred_type` for `user_id`.
    async fn delete_credentials(
        &self,
        user_id: &str,
        cred_type: &str,
    ) -> Result<u64, crate::auth::error::AuthError> {
        let key = format!("{user_id}:{cred_type}");
        let mut creds = self.lock()?;
        if let Some(list) = creds.remove(&key) {
            Ok(list.len() as u64)
        } else {
            Ok(0)
        }
    }

    /// Atomically claims `matched_step` for a TOTP credential if it exceeds `last_used_step`.
    async fn claim_totp_step(
        &self,
        user_id: &str,
        credential_id: &str,
        matched_step: u64,
    ) -> Result<bool, crate::auth::error::AuthError> {
        let key = format!("{user_id}:totp");
        let mut creds = self.lock()?;
        let Some(list) = creds.get_mut(&key) else {
            return Ok(false);
        };
        for val in list.iter_mut() {
            if let Some(obj) = val.as_object_mut() {
                if obj
                    .get("credential_id")
                    .or_else(|| obj.get("id"))
                    .and_then(|v| v.as_str())
                    == Some(credential_id)
                {
                    let current = obj
                        .get("last_used_step")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    if matched_step > current {
                        obj.insert(
                            "last_used_step".to_string(),
                            serde_json::json!(matched_step),
                        );
                        return Ok(true);
                    } else {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Counters are only reclaimed by a later `decrement` on their own key,
    /// so a challenge that is minted and never submitted — the common case —
    /// would otherwise leak an entry for the life of the process. `init_counter`
    /// sweeps opportunistically, in the same spirit as `insert_if_absent`.
    #[tokio::test]
    async fn init_counter_sweeps_expired_counters_under_other_keys() {
        let store = MemoryStore::<String>::new();

        for i in 0..5 {
            store
                .init_counter(&format!("abandoned-{i}"), 3, Duration::from_millis(10))
                .await
                .unwrap();
        }
        assert_eq!(store.counters.lock().unwrap().len(), 5);

        tokio::time::sleep(Duration::from_millis(30)).await;

        store
            .init_counter("fresh", 3, Duration::from_secs(10))
            .await
            .unwrap();

        let held = store.counters.lock().unwrap().len();
        assert_eq!(
            held, 1,
            "expired counters should have been swept, {held} still held"
        );
    }

    #[tokio::test]
    async fn test_get_set_delete() {
        let store = MemoryStore::<String>::new();

        assert_eq!(store.get("key1").await.unwrap(), None);

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

        store.delete("key1").await.unwrap();
        assert_eq!(store.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let store = MemoryStore::<String>::new();

        store
            .set("key1", "value1".to_string(), Duration::from_millis(10))
            .await
            .unwrap();
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));

        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(store.get("key1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_atomic_consume() {
        let store = MemoryStore::<String>::new();

        store
            .set("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        // Consume returns the value and deletes it
        let value = store.consume("key1").await.unwrap();
        assert_eq!(value, Some("value1".to_string()));

        // Second consume returns None
        let value2 = store.consume("key1").await.unwrap();
        assert_eq!(value2, None);
    }

    #[tokio::test]
    async fn test_insert_if_absent_first_call_succeeds() {
        let store = MemoryStore::<String>::new();

        let inserted = store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted);
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_insert_if_absent_second_call_fails_and_keeps_the_first_value() {
        let store = MemoryStore::<String>::new();

        assert!(store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap());

        // A second insert under the same key — the replay case — must be
        // rejected, and must not clobber the value the first insert wrote.
        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!inserted_again);
        assert_eq!(store.get("key1").await.unwrap(), Some("value1".to_string()));
    }

    /// A sub-second TTL must still block a same-key replay presented
    /// immediately after — same property `redis.rs`'s identically named
    /// test checks. Unlike Redis, this alone does not regression-test the
    /// floor fix for *this* backend: two `insert_if_absent` calls back to
    /// back in-process complete well within 10ms regardless, so the second
    /// call finds the first entry still live either way. The
    /// `_with_zero_ttl_` test below is what actually exercises the fixed
    /// code path — `Duration::ZERO` guarantees the entry is already
    /// (barely) past its own `expires_at` by the time the very next call
    /// checks it, sub-millisecond timing or not.
    #[tokio::test]
    async fn test_insert_if_absent_with_sub_second_ttl_still_blocks_a_replay() {
        let store = MemoryStore::<String>::new();

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
    /// the same bug — and the case `check_and_record_dpop_jti` actually
    /// reaches when its `expires_at` has already elapsed by the time it
    /// computes a TTL from it.
    #[tokio::test]
    async fn test_insert_if_absent_with_zero_ttl_still_blocks_a_replay() {
        let store = MemoryStore::<String>::new();

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

    #[tokio::test]
    async fn test_insert_if_absent_allows_reuse_after_expiry() {
        let store = MemoryStore::<String>::new();

        // A whole second, not a sub-second value: `ttl_ceil_secs` floors
        // any sub-second TTL up to a full second (see the regression tests
        // below), so a shorter requested TTL would not actually have
        // expired yet by the time this test's sleep is over.
        store
            .insert_if_absent("key1", "value1".to_string(), Duration::from_secs(1))
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let inserted_again = store
            .insert_if_absent("key1", "value2".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(inserted_again);
        assert_eq!(store.get("key1").await.unwrap(), Some("value2".to_string()));
    }

    /// `insert_if_absent` is the only primitive an insert-only key space
    /// (e.g. a DPoP proof's `jti`, unique per proof) ever calls — nothing
    /// ever revisits the same key the way `get`/`consume` are revisited for
    /// server-issued values. Without an opportunistic sweep, an expired
    /// entry under a never-repeated key would sit in the map forever,
    /// leaking one entry per call for the life of the process. This proves
    /// the map's size actually shrinks, not just that expired entries are
    /// unreachable through `get`.
    #[tokio::test]
    async fn test_insert_if_absent_reclaims_expired_entries_under_other_keys() {
        let store = MemoryStore::<String>::new();

        for i in 0..50 {
            store
                .insert_if_absent(
                    &format!("jti-{i}"),
                    "spent".to_string(),
                    // A whole second, not a sub-second value — see
                    // `test_insert_if_absent_allows_reuse_after_expiry`'s
                    // comment on why `ttl_ceil_secs` makes that necessary.
                    Duration::from_secs(1),
                )
                .await
                .unwrap();
        }
        assert_eq!(store.len(), 50);

        tokio::time::sleep(Duration::from_millis(1100)).await;

        // A single insert under a brand-new key must sweep every expired
        // entry from the previous batch, even though none of their keys
        // are ever looked up again.
        store
            .insert_if_absent("jti-new", "spent".to_string(), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(
            store.len(),
            1,
            "expired insert-only entries under other keys must be swept, not retained forever"
        );
    }

    /// The sweep's expiry queue can hold a stale entry for a key that was
    /// later reinserted with a fresh, longer TTL (`insert_if_absent`
    /// allows reuse once a key's own entry expires — see the test above).
    /// The sweep must recognize that stale entry as no longer describing
    /// the key's *current* value and leave it alone, not wrongly evict a
    /// live entry just because an old queue record for the same key has
    /// finally come due.
    #[tokio::test]
    async fn test_insert_if_absent_sweep_ignores_a_stale_queue_entry_for_a_reused_key() {
        let store = MemoryStore::<String>::new();

        store
            // A whole second, not a sub-second value — see
            // `test_insert_if_absent_allows_reuse_after_expiry`'s comment
            // on why `ttl_ceil_secs` makes that necessary.
            .insert_if_absent("key1", "first".to_string(), Duration::from_secs(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Reuses "key1" with a long TTL — this pushes a second, newer
        // queue entry for the same key; the first (now-expired) one is
        // still sitting in the queue behind it.
        assert!(store
            .insert_if_absent("key1", "second".to_string(), Duration::from_secs(10))
            .await
            .unwrap());

        // Any other insert drives the sweep, which will reach that stale
        // first queue entry for "key1" — it must be discarded as a no-op,
        // not treated as license to remove "key1"'s current, still-live
        // value.
        store
            .insert_if_absent("key2", "unrelated".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        assert_eq!(
            store.get("key1").await.unwrap(),
            Some("second".to_string()),
            "a stale queue entry for a reused key must not evict its current value"
        );
    }

    /// The property the whole replay-guard feature depends on: under real
    /// concurrency, two racing inserts of the same key must never both
    /// report success.
    #[tokio::test]
    async fn test_insert_if_absent_is_atomic_under_concurrency() {
        let store = Arc::new(MemoryStore::<u32>::new());
        let mut handles = Vec::new();
        for i in 0..50u32 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .insert_if_absent("shared-key", i, Duration::from_secs(10))
                    .await
                    .unwrap()
            }));
        }

        let mut successes = 0;
        for handle in handles {
            if handle.await.unwrap() {
                successes += 1;
            }
        }
        assert_eq!(successes, 1, "exactly one racing insert must win");
    }

    #[tokio::test]
    async fn test_indexed_store() {
        let store = MemoryStore::<String>::new();

        store
            .set_indexed("pk1", "sk1", "value1".to_string(), Duration::from_secs(10))
            .await
            .unwrap();

        // Get by primary key
        assert_eq!(store.get("pk1").await.unwrap(), Some("value1".to_string()));

        // Get by index
        assert_eq!(
            store.get_by_index("sk1").await.unwrap(),
            Some("value1".to_string())
        );

        // Consume primary key cleans up entry
        let _ = store.consume("pk1").await.unwrap();

        // Next get by index should return None (and internally clean up the orphaned index)
        assert_eq!(store.get_by_index("sk1").await.unwrap(), None);
    }

    #[cfg(any(feature = "webauthn", feature = "totp", feature = "recovery-codes"))]
    #[tokio::test]
    async fn test_memory_credential_store_totp_step_claim() {
        use crate::auth::CredentialStore;
        let store = MemoryCredentialStore::new();

        store
            .save_credential(
                "alice",
                "totp",
                serde_json::json!({
                    "credential_id": "cred1",
                    "secret": "ABC",
                    "last_used_step": 0
                }),
            )
            .await
            .unwrap();

        assert!(store.claim_totp_step("alice", "cred1", 50).await.unwrap());
        assert!(!store.claim_totp_step("alice", "cred1", 50).await.unwrap());
        assert!(!store.claim_totp_step("alice", "cred1", 49).await.unwrap());
        assert!(store.claim_totp_step("alice", "cred1", 51).await.unwrap());
        assert!(!store.claim_totp_step("bob", "cred1", 52).await.unwrap());
    }
}
