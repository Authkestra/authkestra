//! Verifier configuration.

use std::collections::HashSet;
use std::time::Duration;

use jsonwebtoken::Algorithm;

/// Static configuration for [`crate::verify`].
///
/// `alg` never comes from either token — it is always looked up here. Symmetric algorithms
/// (`HS256`/`HS384`/`HS512`) must never appear in `allowed_algs`: [`VerifierConfig::new`] filters
/// them out defensively, and `verify()` *also* hard-rejects the whole HMAC family unconditionally
/// regardless of what a caller manages to put in `allowed_algs`. This scheme's private key never
/// leaves the device, so there is no symmetric secret the verifier could ever legitimately share
/// with a signer — belt and braces, not a suggestion.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifierConfig {
    /// Attestation `iss` values this verifier trusts.
    pub trusted_issuers: HashSet<String>,
    /// Algorithms accepted for the attestation and — unless [`VerifierConfig::device_algs`] is
    /// set — for the request signature too. Must be asymmetric only — see the type-level docs
    /// above.
    pub allowed_algs: Vec<Algorithm>,
    /// Algorithms accepted for the request signature (the device key), when they differ from
    /// the issuer's. `None` means "the same as `allowed_algs`", which is what
    /// [`VerifierConfig::new`] sets, so existing configurations behave as before. Profile v1
    /// ([`VerifierConfig::profile_v1`]) narrows the device to ES256 and EdDSA while still
    /// trusting RS256 issuers.
    pub device_algs: Option<Vec<Algorithm>>,
    /// Clock skew tolerance applied to both the attestation's and the signature's freshness
    /// windows.
    pub max_clock_skew: Duration,
    /// Upper bound on `sig.exp - sig.iat`. Rejects long-lived signatures outright even if `exp`
    /// itself is still in the future — a short-lived signing key policy is only meaningful if
    /// the lifetime is bounded independently of the clock.
    pub max_signature_lifetime: Duration,
    /// The audience this verifier expects requests to be signed for (`sig.aud`). Prevents a
    /// signature captured for one service being replayed against another.
    pub audience: String,
}

impl VerifierConfig {
    /// Builds a config, silently dropping any symmetric algorithm from `allowed_algs`.
    ///
    /// Dropping rather than erroring keeps this ergonomic for the common case (a caller passes
    /// `[Algorithm::ES256]` and never has to think about it) while still making the
    /// "asymmetric only" rule impossible to defeat by misconfiguration — the algorithm-family
    /// check inside `verify()` is the actual enforcement point either way.
    pub fn new(
        trusted_issuers: impl IntoIterator<Item = impl Into<String>>,
        allowed_algs: impl IntoIterator<Item = Algorithm>,
        max_clock_skew: Duration,
        max_signature_lifetime: Duration,
        audience: impl Into<String>,
    ) -> Self {
        let allowed_algs: Vec<Algorithm> = allowed_algs
            .into_iter()
            .filter(|alg| !is_symmetric(*alg))
            .collect();

        Self {
            trusted_issuers: trusted_issuers.into_iter().map(Into::into).collect(),
            allowed_algs,
            device_algs: None,
            max_clock_skew,
            max_signature_lifetime,
            audience: audience.into(),
        }
    }

    /// A configuration with device-signature profile v1's parameters
    /// (`docs/rfc-014-devsig-profile-v1.md`):
    ///
    /// - attestations signed with ES256, EdDSA or RS256 (each with a `kid`);
    /// - request signatures with ES256 or EdDSA (ES256 is the one every client supports);
    /// - a clock tolerance of [`RECOMMENDED_CLOCK_SKEW`](crate::RECOMMENDED_CLOCK_SKEW) (30 s)
    ///   and a longest signature of [`MAX_SIGNATURE_LIFETIME`](crate::MAX_SIGNATURE_LIFETIME)
    ///   (300 s).
    pub fn profile_v1(
        trusted_issuers: impl IntoIterator<Item = impl Into<String>>,
        audience: impl Into<String>,
    ) -> Self {
        Self::new(
            trusted_issuers,
            [Algorithm::ES256, Algorithm::EdDSA, Algorithm::RS256],
            crate::profile::RECOMMENDED_CLOCK_SKEW,
            crate::profile::MAX_SIGNATURE_LIFETIME,
            audience,
        )
        .with_device_algs([Algorithm::ES256, Algorithm::EdDSA])
    }

    /// Restricts the request signature (the device key) to `algs`, independently of the
    /// attestation's `allowed_algs`. Symmetric algorithms are dropped, as in [`Self::new`].
    pub fn with_device_algs(mut self, algs: impl IntoIterator<Item = Algorithm>) -> Self {
        self.device_algs = Some(algs.into_iter().filter(|alg| !is_symmetric(*alg)).collect());
        self
    }

    /// The algorithms accepted for the request signature.
    pub fn device_algs(&self) -> &[Algorithm] {
        self.device_algs.as_deref().unwrap_or(&self.allowed_algs)
    }
}

pub(crate) fn is_symmetric(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}
