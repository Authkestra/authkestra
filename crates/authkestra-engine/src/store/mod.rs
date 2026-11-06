use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Internal store error: {0}")]
    Internal(String),
    #[error("Not found")]
    NotFound,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[async_trait]
pub trait KvStore<T>: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<T>, StoreError>;
    async fn set(&self, key: &str, value: T, ttl: Duration) -> Result<(), StoreError>;
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// Backends that can atomically fetch-and-remove a value implement this.
#[async_trait]
pub trait AtomicConsume<T: Sync>: KvStore<T> {
    /// Atomically fetches and removes the value stored under `key`.
    async fn consume(&self, key: &str) -> Result<Option<T>, StoreError>;

    /// Atomically removes the value stored under `key` only if its current
    /// value matches `expected`.
    ///
    /// Returns `Ok(true)` if the matching entry was removed, or `Ok(false)` if
    /// the key was absent, expired, or held a different value.
    async fn delete_if_eq(&self, key: &str, expected: &T) -> Result<bool, StoreError> {
        let _ = (key, expected);
        Err(StoreError::Internal(
            "delete_if_eq not supported by this store".to_string(),
        ))
    }
}

/// Backends that can atomically insert a value only if no value is
/// currently stored under `key` implement this.
///
/// This is the complement of [`AtomicConsume`], not a duplicate of it:
/// `AtomicConsume` is for values the *server* creates and later atomically
/// fetches-and-removes (an authorization code, say — the key is only ever
/// seen after this server put it there). `AtomicInsert` is for values whose
/// key is supplied by the *caller* and was never stored by this server
/// first — the shape a replay guard needs, e.g. a DPoP proof's `jti`, which
/// a client generates and this server has never seen before the first time
/// it's presented.
#[async_trait]
pub trait AtomicInsert<T>: KvStore<T> {
    /// Inserts `value` under `key` only if `key` does not already hold a
    /// value. Returns `Ok(true)` if the insert happened (the key was
    /// fresh) and `Ok(false)` if a value was already present (the key was
    /// already claimed — e.g. a replay). Must be a single atomic
    /// operation: a check-then-set built from `get` followed by `set` is a
    /// TOCTOU race that defeats the entire purpose of a replay guard.
    async fn insert_if_absent(
        &self,
        key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<bool, StoreError>;
}

/// Backends that can atomically decrement a counter implement this.
///
/// The third of the atomic primitives, and the one that exists because a
/// count cannot be maintained safely with [`KvStore`] alone. Reading a
/// counter, subtracting one and writing it back is the same check-then-set
/// race [`AtomicInsert`] was added to avoid: two concurrent callers both read
/// 3 and both write 2, so a caller who parallelises gets far more decrements
/// than the counter permits. For a retry budget on a guessable secret that is
/// not a rounding error — it is the difference between a limit and the
/// appearance of one.
///
/// The counter is deliberately a bare integer under its own key rather than a
/// field inside a stored value. Decrementing a field inside a serialised
/// record would mean read-modify-write at the backend too, or JSON surgery
/// inside a Lua script; an integer key is something every backend can already
/// change atomically (`DECR` on Redis, a mutex in memory, `UPDATE ...
/// RETURNING` in SQL).
///
/// See `docs/rfc-011-otp.md` §4.3 for the case that motivated it.
#[async_trait]
pub trait AtomicDecrement<T>: KvStore<T> {
    /// Start a counter at `value`, replacing any existing one under `key`.
    async fn init_counter(&self, key: &str, value: u32, ttl: Duration) -> Result<(), StoreError>;

    /// Take one from the budget, reporting what remains.
    ///
    /// `Ok(Some(n))` means **this call took an attempt** and `n` remain.
    /// `Ok(Some(0))` therefore means this call took the *last* one.
    ///
    /// `Ok(None)` means no attempt was available: no counter under `key`
    /// (never set, or expired), or one already at zero. A caller treating
    /// that as "no attempts left" is correct; a caller treating it as
    /// "unlimited" has inverted the guard.
    ///
    /// The distinction matters and is not cosmetic. An earlier version of
    /// this contract saturated instead, returning `Some(0)` both for "took
    /// the last attempt" and "was already spent" — indistinguishable states,
    /// so a caller could not tell whether the budget had authorised the
    /// operation it was about to perform. Never returning a count for an
    /// attempt that was not granted removes the ambiguity at the source.
    ///
    /// A spent counter stays spent: repeated calls keep reporting `None`
    /// rather than wrapping. Must be a single atomic operation.
    async fn decrement(&self, key: &str) -> Result<Option<u32>, StoreError>;
}

/// Rounds a [`Duration`] up to the nearest whole second, flooring at 1.
///
/// Every [`AtomicInsert`] backend whose storage only expresses TTL in
/// whole seconds (Redis's `EX`, and the `expires_at` column every SQL
/// backend uses) needs this same conversion, and needs it to round up:
/// `insert_if_absent`'s return value is a security-critical replay
/// signal, not a best-effort cache write. Truncating instead (a plain
/// `.as_secs()`, or `.as_secs().max(1)`) would silently disable the
/// replay guard for any caller using a sub-second TTL (e.g. a DPoP
/// freshness window configured in milliseconds) — a 1ms TTL would
/// truncate to `expires_at == now`, meaning the row is already expired by
/// the time anyone could observe it, and every subsequent call with the
/// same key would also see no live entry and also report "fresh". This
/// bug was found and fixed for the Redis backend first (authkestra#277
/// review) and, having no shared definition to fall to, was independently
/// re-introduced in each SQL backend rather than caught by one fix.
pub fn ttl_ceil_secs(ttl: Duration) -> u64 {
    ttl.as_secs()
        .saturating_add(u64::from(ttl.subsec_nanos() > 0))
        .max(1)
}

/// Backends that can atomically write a value under a primary key while
/// also maintaining a secondary lookup key implement this.
#[async_trait]
pub trait IndexedKvStore<T>: KvStore<T> {
    async fn set_indexed(
        &self,
        primary_key: &str,
        secondary_key: &str,
        value: T,
        ttl: Duration,
    ) -> Result<(), StoreError>;
    async fn get_by_index(&self, secondary_key: &str) -> Result<Option<T>, StoreError>;
}

#[cfg(feature = "memory")]
pub mod memory;
#[cfg(all(
    feature = "memory",
    any(feature = "webauthn", feature = "totp", feature = "recovery-codes")
))]
pub use memory::MemoryCredentialStore;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(any(
    feature = "sql-postgres",
    feature = "sql-sqlite",
    feature = "sql-mysql"
))]
pub mod sql;
pub mod sqlite_url;
pub mod traits;
