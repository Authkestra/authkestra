//! Rejection reasons for the device-signature verification algorithm.
//!
//! Every variant corresponds to exactly one named rejection in the algorithm this crate
//! implements (see the crate-level docs), so a caller — or a conformance test — can assert on
//! the precise reason a request was rejected rather than just "it failed".

use thiserror::Error;

/// Why [`crate::verify`] rejected a request. Never carries the raw cryptographic material that
/// caused the rejection — only enough to log or monitor safely.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// `X-Signature` and/or `X-Attestation` absent.
    #[error("missing_credential: X-Signature and X-Attestation are both required")]
    MissingCredential,

    /// One of the two headers is not a syntactically valid compact JWS, or a claim set does not
    /// have profile v1's shape (for the attestation: `iss`, `sub`, `did`, `iat`, `exp`,
    /// `cnf.jkt`, and an `att` that is a JSON object).
    #[error("malformed: {0}")]
    Malformed(String),

    /// `alg` is not in the configured allow-list, is `none`, or is a symmetric algorithm
    /// (HS256/384/512) — rejected unconditionally regardless of configuration, because this
    /// scheme is asymmetric-only by construction (the private key never leaves the device).
    #[error("bad_alg: {0}")]
    BadAlg(String),

    /// The attestation's `iss` is not one of the configured trusted issuers.
    #[error("untrusted_issuer: {0}")]
    UntrustedIssuer(String),

    /// The attestation's `kid` is not present in the cached Issuer JWKS.
    #[error("unknown_kid: {0}")]
    UnknownKid(String),

    /// The attestation's signature does not verify against the resolved Issuer key.
    #[error("bad_attestation: {0}")]
    BadAttestation(String),

    /// `now` falls outside `[att.iat - skew, att.exp + skew]`.
    #[error("attestation_expired")]
    AttestationExpired,

    /// The attestation's `att.status` is not `"active"`.
    #[error("device_not_active")]
    DeviceNotActive,

    /// The embedded `jwk` (from the request signature's protected header) is missing, is not a
    /// public key of an allowed type, carries a private component (`d`, `p`, `q`, `dp`, `dq`,
    /// `qi`, `k`), or is a key no signature under it could ever prove anything about.
    ///
    /// That last case is a **low-order ("weak") Ed25519 public key**: no private key exists for
    /// one, so it is rejected on its own merits, before verification is attempted, rather than
    /// as a `bad_signature` — the key is the defect, not the signature. See `crate::eddsa` and
    /// [authkestra#242](https://github.com/marcjazz/authkestra/issues/242).
    #[error("bad_jwk: {0}")]
    BadJwk(String),

    /// **The security-critical rejection.** `thumbprint(sig.header.jwk) != att.claims.cnf.jkt`.
    ///
    /// An attacker who presents a victim's valid attestation (it is public — it travels in
    /// every request) alongside a request signed with the attacker's *own* key lands here. The
    /// attestation's signature verifies fine (it's genuinely from the Issuer) and the request
    /// signature verifies fine (against the attacker's own, genuinely-held key) — only this
    /// thumbprint comparison detects that the two credentials do not describe the same key.
    /// Skipping, reordering, or short-circuiting this check is a total authentication bypass.
    #[error("key_not_bound: embedded jwk thumbprint does not match attestation cnf.jkt")]
    KeyNotBound,

    /// The request signature does not verify against the embedded `jwk`.
    #[error("bad_signature: {0}")]
    BadSignature(String),

    /// `now` falls outside `[sig.iat - skew, sig.exp + skew]`.
    #[error("signature_expired")]
    SignatureExpired,

    /// `sig.exp - sig.iat` exceeds the configured maximum signature lifetime.
    #[error("lifetime_too_long")]
    LifetimeTooLong,

    /// `sig.mth != request.method`.
    #[error("method_mismatch")]
    MethodMismatch,

    /// `sig.pth != request.path`.
    #[error("path_mismatch")]
    PathMismatch,

    /// `sig.aud != expected_audience`.
    #[error("audience_mismatch")]
    AudienceMismatch,

    /// `sig.qsh` disagrees with the live request's query string: it is absent while a query is
    /// present, present while there is none (profile v1: a hash on one side only is a
    /// mismatch), or not the hex SHA-256 of the raw query.
    #[error("query_mismatch")]
    QueryMismatch,

    /// `sig.bdh` disagrees with the live request's body: it is absent while a body is present,
    /// present while the body is empty (profile v1: the body was stripped in transit), or not the
    /// hex SHA-256 of the raw body bytes.
    #[error("body_mismatch")]
    BodyMismatch,

    /// `jti` was already seen, or the replay store was unreachable. These reject identically —
    /// an unreachable replay store must never be treated as "no replay recorded, so allow".
    #[error("replay_detected")]
    ReplayDetected,

    /// The request body exceeded the configured maximum size before it could be hashed. Only
    /// produced by the optional framework-integration layer/middleware (in `authkestra-axum` or
    /// `authkestra-actix`), which must buffer the body to compute `bdh` — never by
    /// [`crate::verify`] itself, which takes body bytes the caller already has.
    #[error("body_too_large: request body exceeds the configured maximum of {0} bytes")]
    BodyTooLarge(usize),
}

impl VerifyError {
    /// The machine-readable rejection code (e.g. `"key_not_bound"`), stable across changes to
    /// the `Display` message wording. Suitable for metrics labels and log fields.
    pub fn code(&self) -> &'static str {
        match self {
            VerifyError::MissingCredential => "missing_credential",
            VerifyError::Malformed(_) => "malformed",
            VerifyError::BadAlg(_) => "bad_alg",
            VerifyError::UntrustedIssuer(_) => "untrusted_issuer",
            VerifyError::UnknownKid(_) => "unknown_kid",
            VerifyError::BadAttestation(_) => "bad_attestation",
            VerifyError::AttestationExpired => "attestation_expired",
            VerifyError::DeviceNotActive => "device_not_active",
            VerifyError::BadJwk(_) => "bad_jwk",
            VerifyError::KeyNotBound => "key_not_bound",
            VerifyError::BadSignature(_) => "bad_signature",
            VerifyError::SignatureExpired => "signature_expired",
            VerifyError::LifetimeTooLong => "lifetime_too_long",
            VerifyError::MethodMismatch => "method_mismatch",
            VerifyError::PathMismatch => "path_mismatch",
            VerifyError::AudienceMismatch => "audience_mismatch",
            VerifyError::QueryMismatch => "query_mismatch",
            VerifyError::BodyMismatch => "body_mismatch",
            VerifyError::ReplayDetected => "replay_detected",
            VerifyError::BodyTooLarge(_) => "body_too_large",
        }
    }
}
