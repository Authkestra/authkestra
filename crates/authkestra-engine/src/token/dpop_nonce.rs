//! Server-issued DPoP nonces (RFC 9449 §8 and §9).
//!
//! Without a nonce, a DPoP proof is fresh for as long as its `iat` says it is — and `iat` is
//! chosen by the client, so a proof pre-generated on a compromised device (or a clock set
//! forward) stays usable for the whole freshness window after it leaks. A server nonce bounds
//! that: the server says which value the next proof must carry, and a proof without it is
//! answered `use_dpop_nonce` together with a `DPoP-Nonce` header the client retries with.
//!
//! [`DpopNonces`] is **stateless**: a nonce is the time window it was issued in plus an
//! HMAC-SHA256 of that window under a server secret, and it is accepted in its own window and
//! the next one. Nothing is stored, so there is no store to scale or to fail, and every node
//! that shares the secret accepts every other node's nonces. The cost of statelessness is that
//! a nonce is not single-use — it is a freshness bound, which is what RFC 9449 §8 asks of it;
//! single use is the proof's `jti`, tracked by the replay store as before.
//!
//! Both ends use it: `authkestra-op`'s token endpoint (opt in with
//! `CompositeOpStore::with_dpop_nonces`) and a resource server.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use super::cert_binding::constant_time_eq;

/// The OAuth error a server answers when a DPoP proof lacks a valid nonce (RFC 9449 §8, §9).
pub const USE_DPOP_NONCE: &str = "use_dpop_nonce";

/// The response header that carries a fresh nonce (RFC 9449 §8.1).
pub const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";

/// The default window: a nonce stays acceptable for between five and ten minutes.
pub const DEFAULT_NONCE_WINDOW: Duration = Duration::from_secs(300);

/// Domain separation, so the secret cannot be used to forge anything else that is an HMAC of
/// eight bytes.
const DOMAIN: &[u8] = b"authkestra-dpop-nonce-v1";

/// How far a node's clock may run ahead of another's that shares the secret: a nonce
/// for the next window is accepted this close to the boundary, and no earlier.
pub const NODE_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Bytes of the MAC kept in a nonce: 128 bits, far beyond what an online guess can reach in a
/// window.
const MAC_LEN: usize = 16;

/// Issues and checks stateless DPoP nonces. See the module docs.
///
/// ```
/// use authkestra_engine::token::dpop_nonce::DpopNonces;
/// use std::time::Duration;
///
/// let nonces = DpopNonces::new(b"a 32-byte secret shared by every node", Duration::from_secs(300));
/// let nonce = nonces.issue_at(1_800_000_000);
/// assert!(nonces.accepts_at(&nonce, 1_800_000_000 + 400)); // the next window
/// assert!(!nonces.accepts_at(&nonce, 1_800_000_000 + 900)); // two windows later
/// ```
#[derive(Clone)]
pub struct DpopNonces {
    key: Vec<u8>,
    window_secs: u64,
}

impl fmt::Debug for DpopNonces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the secret.
        f.debug_struct("DpopNonces")
            .field("window_secs", &self.window_secs)
            .finish_non_exhaustive()
    }
}

impl DpopNonces {
    /// Nonces under `secret`, each valid in the `window` it was issued in and the next one.
    ///
    /// Every node that must accept another's nonces needs the same secret; use at least 32
    /// random bytes. A `window` under one second is raised to one second.
    pub fn new(secret: impl AsRef<[u8]>, window: Duration) -> Self {
        Self {
            key: secret.as_ref().to_vec(),
            window_secs: window.as_secs().max(1),
        }
    }

    /// Nonces under a fresh random 32-byte secret: right for a single node, whose nonces no
    /// other node needs to accept. A restart invalidates every outstanding nonce, which costs a
    /// client one `use_dpop_nonce` round trip.
    pub fn random(window: Duration) -> Self {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret);
        Self::new(secret, window)
    }

    /// The window length.
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.window_secs)
    }

    /// A nonce for now.
    pub fn issue(&self) -> String {
        self.issue_at(unix_now())
    }

    /// A nonce for the Unix time `now`.
    pub fn issue_at(&self, now: i64) -> String {
        let window = self.window_of(now);
        let mut bytes = Vec::with_capacity(8 + MAC_LEN);
        bytes.extend_from_slice(&window.to_be_bytes());
        bytes.extend_from_slice(&self.mac(window));
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Whether `nonce` is acceptable now.
    pub fn accepts(&self, nonce: &str) -> bool {
        self.accepts_at(nonce, unix_now())
    }

    /// Whether `nonce` is acceptable at the Unix time `now`: issued under this secret, in the
    /// current window or the one before, or in the next one when `now` is within
    /// [`NODE_CLOCK_SKEW`] of its start (a node whose clock runs ahead issued it).
    pub fn accepts_at(&self, nonce: &str, now: i64) -> bool {
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(nonce) else {
            return false;
        };
        if bytes.len() != 8 + MAC_LEN {
            return false;
        }
        let mut window = [0u8; 8];
        window.copy_from_slice(&bytes[..8]);
        let window = u64::from_be_bytes(window);
        let current = self.window_of(now);
        let next_is_near = current
            .checked_add(1)
            .and_then(|next| next.checked_mul(self.window_secs))
            .is_some_and(|start| {
                start.saturating_sub(u64::try_from(now).unwrap_or(0)) <= NODE_CLOCK_SKEW.as_secs()
            });
        let in_range = window == current
            || Some(window) == current.checked_sub(1)
            || (next_is_near && Some(window) == current.checked_add(1));
        if !in_range {
            return false;
        }
        let expected = URL_SAFE_NO_PAD.encode(self.mac(window));
        constant_time_eq(&URL_SAFE_NO_PAD.encode(&bytes[8..]), &expected)
    }

    /// Computes the time-bucket window index for the given Unix epoch timestamp.
    fn window_of(&self, now: i64) -> u64 {
        u64::try_from(now).unwrap_or(0) / self.window_secs
    }

    /// Computes the truncated HMAC-SHA256 for a given time-bucket window.
    fn mac(&self, window: u64) -> [u8; MAC_LEN] {
        // INVARIANT: `new_from_slice` fails only for MACs with a fixed key size. HMAC takes
        // a key of any length (it hashes a longer one and pads a shorter one), so this
        // cannot fail.
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts a key of any length");
        mac.update(DOMAIN);
        mac.update(&window.to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mut out = [0u8; MAC_LEN];
        out.copy_from_slice(&full[..MAC_LEN]);
        out
    }
}

/// The `nonce` claim of a DPoP proof, if it has one.
///
/// Reads the payload without checking anything: call it **only on a proof
/// [`super::dpop::verify_dpop_proof`] has already accepted**, whose signature covers the payload
/// this reads.
pub fn dpop_proof_nonce(compact_jws: &str) -> Option<String> {
    let payload = compact_jws.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("nonce")?.as_str().map(str::to_owned)
}

/// Returns the current Unix epoch time in seconds, or 0 if system time is before epoch.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_800_000_000;

    fn nonces() -> DpopNonces {
        DpopNonces::new(b"test secret, never use", Duration::from_secs(300))
    }

    #[test]
    fn a_nonce_is_accepted_in_its_window_and_the_next_only() {
        let n = nonces();
        let nonce = n.issue_at(T);
        let start = T - T % 300;
        assert!(n.accepts_at(&nonce, start));
        assert!(n.accepts_at(&nonce, start + 299));
        assert!(n.accepts_at(&nonce, start + 300));
        assert!(n.accepts_at(&nonce, start + 599));
        assert!(!n.accepts_at(&nonce, start + 600));
        assert!(
            !n.accepts_at(&nonce, start - 31),
            "not long before it was issued"
        );
    }

    #[test]
    fn a_node_whose_clock_runs_ahead_is_tolerated_near_the_boundary_only() {
        // Another node, 20 s ahead, already issued a nonce for the next window.
        let n = nonces();
        let start = T - T % 300;
        let from_the_next_window = n.issue_at(start + 300);
        assert!(n.accepts_at(&from_the_next_window, start + 300 - 20));
        assert!(n.accepts_at(&from_the_next_window, start + 300 - 30));
        assert!(!n.accepts_at(&from_the_next_window, start + 300 - 31));
        // Two windows ahead is never accepted.
        let two_ahead = n.issue_at(start + 600);
        assert!(!n.accepts_at(&two_ahead, start + 300 - 1));
    }

    #[test]
    fn another_secret_does_not_accept_it() {
        let nonce = nonces().issue_at(T);
        let other = DpopNonces::new(b"another secret", Duration::from_secs(300));
        assert!(!other.accepts_at(&nonce, T));
    }

    #[test]
    fn a_forged_window_is_refused() {
        let n = nonces();
        let nonce = n.issue_at(T - 3_600);
        // Move the window forward but keep the MAC: the MAC no longer matches.
        let mut bytes = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
        bytes[..8].copy_from_slice(&n.window_of(T).to_be_bytes());
        assert!(!n.accepts_at(&URL_SAFE_NO_PAD.encode(bytes), T));
    }

    #[test]
    fn garbage_is_refused() {
        let n = nonces();
        for nonce in ["", "not base64!", "AAAA", &"A".repeat(200)] {
            assert!(!n.accepts_at(nonce, T), "{nonce:?}");
        }
    }

    #[test]
    fn issuing_is_deterministic_and_secret_free_in_debug() {
        let n = nonces();
        assert_eq!(n.issue_at(T), n.issue_at(T + 1));
        assert!(!format!("{n:?}").contains("secret"));
    }

    #[test]
    fn random_nonces_round_trip() {
        let n = DpopNonces::random(DEFAULT_NONCE_WINDOW);
        assert!(n.accepts(&n.issue()));
        assert_eq!(n.window(), DEFAULT_NONCE_WINDOW);
    }

    #[test]
    fn a_zero_window_is_raised_to_one_second() {
        assert_eq!(
            DpopNonces::new(b"k", Duration::ZERO).window(),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn the_nonce_claim_is_read_from_the_payload() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"htm":"POST","nonce":"abc"}"#);
        assert_eq!(
            dpop_proof_nonce(&format!("h.{payload}.s")).as_deref(),
            Some("abc")
        );
        let none = URL_SAFE_NO_PAD.encode(br#"{"htm":"POST"}"#);
        assert_eq!(dpop_proof_nonce(&format!("h.{none}.s")), None);
        assert_eq!(dpop_proof_nonce("no-dots"), None);
    }
}
