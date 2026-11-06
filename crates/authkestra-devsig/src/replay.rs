//! Replay protection.
//!
//! Deliberately not authkestra's `SessionStore`: this holds short-TTL, single-use `jti` markers,
//! not sessions, and has entirely different lifecycle semantics (insert-once, never updated,
//! evicted on TTL rather than on logout).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use thiserror::Error;

/// Failure modes for a replay store. A request must fail closed on *any* `Err` here — not just
/// [`ReplayError::Unavailable`] — meaning `verify()` treats a store outage identically to a
/// genuine replay: reject, never silently allow.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// The store could not be reached (network partition, connection pool exhausted, etc.).
    #[error("replay store unavailable: {0}")]
    Unavailable(String),
}

/// Atomic single-use marker store, keyed by `jti`.
///
/// A real deployment should back this with something shared across every verifier instance in
/// the trust domain (e.g. Redis with `SET key val NX PX ttl`) — if several verifiers each keep an
/// independent local cache, a request replayed to a *different* verifier instance succeeds. See
/// the crate-level docs for the "replay scope" requirement this trait exists to satisfy.
#[async_trait]
pub trait ReplayStore: Send + Sync + 'static {
    /// Atomically records `jti` if and only if it is not already present.
    ///
    /// Returns `Ok(true)` if `jti` was newly inserted (request may proceed), `Ok(false)` if it
    /// was already present (replay — reject). `Err` means the store itself failed; the caller
    /// must treat this identically to `Ok(false)` (fail closed, never fail open).
    async fn put_if_absent(&self, jti: &str, ttl: Duration) -> Result<bool, ReplayError>;
}

struct Entry {
    inserted_at: Instant,
    ttl: Duration,
}

impl Entry {
    /// Returns true if the entry's age exceeds its configured TTL.
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.inserted_at) >= self.ttl
    }
}

/// A `HashMap`-backed [`ReplayStore`] for tests and single-process deployments.
///
/// Expired entries are lazily swept on each call rather than on a background timer — fine for a
/// single process, but this does not share state across processes. Use a distributed store (e.g.
/// Redis) for anything with more than one verifier instance.
#[derive(Default)]
pub struct InMemoryReplayStore {
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryReplayStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn put_if_absent(&self, jti: &str, ttl: Duration) -> Result<bool, ReplayError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().expect("replay store mutex poisoned");

        entries.retain(|_, entry| !entry.is_expired(now));

        if entries.contains_key(jti) {
            return Ok(false);
        }

        entries.insert(
            jti.to_string(),
            Entry {
                inserted_at: now,
                ttl,
            },
        );
        Ok(true)
    }
}

/// A [`ReplayStore`] that always fails — for exercising the fail-closed path in tests (a replay
/// store outage must still reject).
pub struct UnavailableReplayStore;

#[async_trait]
impl ReplayStore for UnavailableReplayStore {
    async fn put_if_absent(&self, _jti: &str, _ttl: Duration) -> Result<bool, ReplayError> {
        Err(ReplayError::Unavailable("simulated outage".to_string()))
    }
}
