//! The orchestrator: runs the full verification algorithm end to end, in the mandated order —
//! cheap checks first, the binding check before anything is allowed to trust the embedded key,
//! replay recorded last and only once everything else has already succeeded.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::attestation;
use crate::config::VerifierConfig;
use crate::error::VerifyError;
use crate::identity::DeviceIdentity;
use crate::jwks::IssuerJwks;
use crate::replay::ReplayStore;
use crate::request::SignedRequest;
use crate::signature;

/// Verifies a device-bound signed request against the configured trust policy.
///
/// `request.signature` and `request.attestation` carry the two credentials (see
/// [`SignedRequest`]); this function is deliberately framework-agnostic so it can be called from
/// a `tower::Layer` (see the optional `axum` feature), a future authkestra trait-based
/// integration, or a plain test harness — the algorithm itself does not care which.
///
/// Order, and why it is load-bearing:
///
/// 1. **Presence** — both credentials must be present. An attestation alone is a bearer token
///    (it is public, travels in every request, and is likely logged); rejecting this case is
///    what keeps the attestation from becoming exactly the weaker-than-normal scheme this design
///    exists to avoid.
/// 2. **Parse + `alg` check** — for both credentials, cheap, before any cryptographic work.
/// 3. **Attestation trust** — issuer, `kid`, signature, expiry, device status.
/// 4. **The binding** — recompute the embedded `jwk`'s RFC 7638 thumbprint and compare it,
///    constant-time, to the attestation's `cnf.jkt`. **This is the step that cannot be inferred
///    from the other two.** An attacker holding a victim's attestation (public, not secret) and
///    their own genuinely-held keypair passes steps 3 and 5 independently and completely; only
///    this comparison detects that the two credentials describe different keys. Skipping,
///    reordering, or short-circuiting it is a total authentication bypass.
/// 5. **Request-signature verification** against that now-bound `jwk`.
/// 6. **Freshness** — skew window, maximum signature lifetime.
/// 7. **Request binding** — method, path, audience, query hash, body hash.
/// 8. **Replay** — recorded last, and fails closed on any store error, not just "already
///    present". A replay store that cannot be reached must reject exactly as if the `jti` had
///    already been seen; falling back to "allow" would silently disable replay protection during
///    an outage, which is worse than rejecting traffic.
pub async fn verify(
    request: &SignedRequest<'_>,
    config: &VerifierConfig,
    jwks: &IssuerJwks,
    replay_store: &dyn ReplayStore,
) -> Result<DeviceIdentity, VerifyError> {
    verify_at(request, config, jwks, replay_store, SystemTime::now()).await
}

/// [`verify`], at the time `now` instead of the system clock.
///
/// For a host that keeps its own clock, and for conformance: the profile v1 vectors
/// (`conformance/devsig-profile-v1/vectors.json`) are minted at fixed timestamps and carry the
/// `now` each one is checked at, so every implementation that runs them — this crate, a client
/// library's verifier, a server under test — reaches the same verdict on any day. Everything
/// else, including the order of the checks and the replay store's behaviour, is [`verify`]'s.
pub async fn verify_at(
    request: &SignedRequest<'_>,
    config: &VerifierConfig,
    jwks: &IssuerJwks,
    replay_store: &dyn ReplayStore,
    now: SystemTime,
) -> Result<DeviceIdentity, VerifyError> {
    // Reported once here rather than at each rejection point inside, matching
    // how `verify_dpop_proof` reports its eleven (#353 tier 1).
    //
    // Some checks already spoke for themselves — the issuer, device status
    // and binding rejections each have their own event, and the binding one
    // says something this boundary cannot, so they stay. But every rejection
    // in `signature.rs` from the request-signature check onward (bad
    // signature, expired, lifetime too long, and the method, path, audience,
    // query and body mismatches) emitted nothing at all, which is eight of
    // the nineteen ways this can refuse a request. A caller sees one
    // flattened `VerifyError` and the adapters map the whole family onto a
    // single 401, so for those eight the reason existed nowhere.
    //
    // Doing it at the boundary rather than adding eight more call sites also
    // means the set cannot drift: a check added later is reported without
    // anyone remembering to report it.
    //
    // `error.code()` carries the stable slug its own doc offers for exactly
    // this; the `Display` text goes alongside for the variants that carry
    // detail. Neither credential is logged: both are the credential.
    let now = unix_seconds(now);
    let outcome = verify_inner(request, config, jwks, replay_store, now).await;

    match &outcome {
        Ok(identity) => tracing::debug!(
            target: "authkestra_devsig",
            subject = %identity.subject,
            device = %identity.device,
            method = %request.method,
            path = %request.path,
            "device-signature request accepted"
        ),
        Err(error) => tracing::warn!(
            target: "authkestra_devsig",
            reason = error.code(),
            %error,
            method = %request.method,
            path = %request.path,
            "device-signature request rejected"
        ),
    }

    outcome
}

/// The verification itself. Split out so [`verify`] can report the outcome in
/// one place; see the comment there.
async fn verify_inner(
    request: &SignedRequest<'_>,
    config: &VerifierConfig,
    jwks: &IssuerJwks,
    replay_store: &dyn ReplayStore,
    now: i64,
) -> Result<DeviceIdentity, VerifyError> {
    // Profile v1 normalisation: an empty value is no value. An empty header is an absent
    // credential (not a malformed one), `?` with nothing after it is no query, and a zero-length
    // body is no body — so `qsh`/`bdh` must then be absent too (see `signature.rs`). Adapters
    // already do the body half; doing all three here keeps every caller on one rule.
    let request = SignedRequest {
        signature: non_empty(request.signature),
        attestation: non_empty(request.attestation),
        method: request.method,
        path: request.path,
        query: non_empty(request.query),
        body: request.body.filter(|b| !b.is_empty()),
    };

    // --- Step 1: PRESENCE ---
    let (sig_token, att_token) = match (request.signature, request.attestation) {
        (Some(s), Some(a)) => (s, a),
        // Not logged here: the boundary reports every rejection uniformly.
        _ => return Err(VerifyError::MissingCredential),
    };

    // --- Step 2: PARSE (both credentials, cheap, before any crypto) ---
    let parsed_att = attestation::parse(att_token, &config.allowed_algs)?;
    let parsed_sig = signature::parse(sig_token, config.device_algs())?;

    // --- Step 3: ATTESTATION TRUST ---
    let att = attestation::verify_trust(&parsed_att, config, jwks, now).await?;

    // --- Steps 4-7: THE BINDING, REQUEST SIGNATURE, FRESHNESS, REQUEST BINDING ---
    let sig = signature::verify_bound_and_signed(&parsed_sig, &request, config, &att.jkt, now)?;

    // --- Step 8: REPLAY — fails closed: a store error rejects exactly like a genuine replay,
    // never falls back to "allow". ---
    let ttl = Duration::from_secs((sig.exp - now).max(0) as u64);
    match replay_store.put_if_absent(&sig.jti, ttl).await {
        Ok(true) => {}
        // These two keep their own events despite the boundary above, because
        // each carries something it cannot see: the `jti` that was replayed,
        // and the store's own error — which flattens into a plain
        // `ReplayDetected`, so a fail-closed outage would otherwise be
        // indistinguishable from a genuine replay in the logs. They are also
        // different kinds of event: one is a client being refused, the other
        // is this service degrading.
        Ok(false) => {
            tracing::warn!(target: "authkestra_devsig", jti = %sig.jti, "jti already seen");
            return Err(VerifyError::ReplayDetected);
        }
        Err(store_err) => {
            tracing::error!(
                target: "authkestra_devsig",
                error = %store_err,
                "replay store unreachable; failing closed"
            );
            return Err(VerifyError::ReplayDetected);
        }
    }

    Ok(DeviceIdentity::new(
        att.sub,
        att.did,
        sig.jwk_thumbprint,
        att.att,
    ))
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty())
}

/// Seconds since the Unix epoch; a time before 1970 counts as negative (and so fails every
/// freshness window) rather than panicking.
fn unix_seconds(now: SystemTime) -> i64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_secs() as i64,
        Err(before) => -(before.duration().as_secs() as i64),
    }
}
