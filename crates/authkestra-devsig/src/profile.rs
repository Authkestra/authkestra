//! Device-signature **profile v1**: the wire contract this crate verifies and the refusal shape
//! every framework adapter answers with.
//!
//! The normative text is `docs/rfc-014-devsig-profile-v1.md`; the shared conformance vectors are
//! `conformance/devsig-profile-v1/vectors.json`, which `tests/profile_v1.rs` runs against
//! [`crate::verify_at`]. Client libraries in other languages (fespalier's
//! `fespalier_sign_keypair`, CrateStack's device-signature provider) vendor that file by commit
//! and run the same vectors, so all three agree on one table instead of three.
//!
//! This module holds the parts of the profile that are not the verification algorithm itself:
//!
//! - the header names and the recommended clock tolerances;
//! - [`Refusal`]: how a [`VerifyError`] goes out on the wire — an HTTP status, a JSON body
//!   `{"error": "<code>"}` and, for a `401`, a `WWW-Authenticate: DeviceSignature
//!   error="<code>"` challenge;
//! - the two refusals `verify()` never produces but an application answers with:
//!   [`Refusal::device_revoked`] (`403`) and [`Refusal::insufficient_user_authentication`]
//!   (`401`, RFC 9470 step-up to the user-present key, see [`crate::KeyRole`]).

use std::time::Duration;

use crate::error::VerifyError;

/// The profile version this crate implements.
pub const PROFILE_VERSION: &str = "devsig-profile-v1";

/// The header carrying the request signature (compact JWS, signed by the device).
pub const SIGNATURE_HEADER: &str = "X-Signature";

/// The header carrying the attestation (compact JWS, signed by the issuer).
pub const ATTESTATION_HEADER: &str = "X-Attestation";

/// The authentication scheme named in a `WWW-Authenticate` challenge.
pub const WWW_AUTHENTICATE_SCHEME: &str = "DeviceSignature";

/// The media type of a refusal body.
pub const REFUSAL_CONTENT_TYPE: &str = "application/json";

/// Profile v1's clock tolerance, applied to both credentials' validity windows.
pub const RECOMMENDED_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Profile v1's longest request signature: `exp - iat` above this is `lifetime_too_long`.
pub const MAX_SIGNATURE_LIFETIME: Duration = Duration::from_secs(300);

/// `403`: the device is revoked. Not produced by [`crate::verify`] (an attestation only says
/// `att.status`); answered by an application that knows the device is revoked from its own
/// state — a revocation list, an SSF/CAEP event — and by re-issuance for a revoked principal.
pub const DEVICE_REVOKED: &str = "device_revoked";

/// `401` (RFC 9470): the request was signed with the ambient key but needs the user-present
/// one. Not produced by [`crate::verify`]; answered by a handler that checks
/// [`crate::DeviceIdentity::key_role`].
pub const INSUFFICIENT_USER_AUTHENTICATION: &str = "insufficient_user_authentication";

/// How a refused request goes out on the wire under profile v1.
///
/// Framework-agnostic on purpose: the axum and actix adapters, and any other host (a CrateStack
/// `AuthProvider`, a hand-written tower layer), render the same three parts — so a client sorts
/// refusals by one table whichever server it talks to.
///
/// ```
/// use authkestra_devsig::VerifyError;
///
/// let refusal = VerifyError::KeyNotBound.refusal();
/// assert_eq!(refusal.status, 401);
/// assert_eq!(refusal.body(), r#"{"error":"key_not_bound"}"#);
/// assert_eq!(
///     refusal.www_authenticate().as_deref(),
///     Some(r#"DeviceSignature error="key_not_bound""#)
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Refusal {
    /// The HTTP status: `401`, except `413` for `body_too_large` and `403` for `device_revoked`.
    pub status: u16,
    /// The stable code, as [`VerifyError::code`] spells it.
    pub error: &'static str,
}

impl Refusal {
    /// `403 {"error": "device_revoked"}`, for an application that knows the device is revoked.
    pub const fn device_revoked() -> Self {
        Self {
            status: 403,
            error: DEVICE_REVOKED,
        }
    }

    /// `401 {"error": "insufficient_user_authentication"}` with an RFC 9470 challenge, for a
    /// handler that needs the user-present key and got a request signed by the ambient one.
    pub const fn insufficient_user_authentication() -> Self {
        Self {
            status: 401,
            error: INSUFFICIENT_USER_AUTHENTICATION,
        }
    }

    /// The JSON body: exactly `{"error":"<code>"}`. Never carries either credential or any
    /// detail of why a check failed beyond the code.
    pub fn body(&self) -> String {
        serde_json::json!({ "error": self.error }).to_string()
    }

    /// The `WWW-Authenticate` value for a `401` (`DeviceSignature error="<code>"`, RFC 6750 §3
    /// style); `None` for any other status. Codes are `[a-z_]` only, so no quoting is needed.
    pub fn www_authenticate(&self) -> Option<String> {
        (self.status == 401).then(|| format!("{WWW_AUTHENTICATE_SCHEME} error=\"{}\"", self.error))
    }
}

impl VerifyError {
    /// The profile v1 refusal for this rejection: its status, code and challenge.
    pub fn refusal(&self) -> Refusal {
        let status = match self {
            VerifyError::BodyTooLarge(_) => 413,
            _ => 401,
        };
        Refusal {
            status,
            error: self.code(),
        }
    }
}
