//! The success output of `verify()`.

use serde_json::Value;

/// Identity established by a request that passed every step of the verification algorithm.
///
/// `subject` and `device` come from the attestation; `key_thumbprint` is recomputed by the
/// verifier from the request signature's embedded `jwk` (it necessarily equals the
/// attestation's `cnf.jkt` — that equality *is* the binding check — but it is threaded through
/// separately here to document that this value was derived from the live request, not merely
/// copied out of the attestation).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceIdentity {
    /// The attestation's `sub` claim — the authenticated identity.
    pub subject: String,
    /// The attestation's `did` claim — the device identifier.
    pub device: String,
    /// The RFC 7638 SHA-256 thumbprint of the request-signature's embedded `jwk`.
    pub key_thumbprint: String,
    /// The attestation's `att` claim — application attributes. Opaque to this crate; surfaced
    /// as-is to the application.
    pub attributes: Value,
}

impl DeviceIdentity {
    /// Builds a `DeviceIdentity` from its parts, **verifying nothing**.
    ///
    /// A value built here carries no proof that any signature, attestation, or key binding was
    /// ever checked; only [`verify()`](crate::verify()) returns a `DeviceIdentity` that means
    /// "this request passed every step of the algorithm". Treat a hand-built value as test data,
    /// never as an authentication result.
    ///
    /// It exists because `DeviceIdentity` is an *output* type: every consumer writes a mapping
    /// from it onto their own principal/session representation, and that mapping is where the
    /// security-relevant defaults live — what an absent `role` attribute grants, for one. With
    /// `#[non_exhaustive]` and no constructor, that mapping could not be unit-tested from
    /// outside this crate at all: a downstream test could not build the input without standing
    /// up a full attestation mint plus a real signature (authkestra#282).
    ///
    /// `#[non_exhaustive]` is deliberately kept — it still stops downstream struct expressions
    /// and exhaustive `match`es from breaking when a field is added — and this constructor is
    /// the supported way through it.
    ///
    /// ```
    /// use authkestra_devsig::DeviceIdentity;
    ///
    /// let identity = DeviceIdentity::new(
    ///     "usr_1".to_owned(),
    ///     "dev_1".to_owned(),
    ///     "jkt-1".to_owned(),
    ///     serde_json::json!({ "role": "user" }),
    /// );
    /// assert_eq!(identity.subject, "usr_1");
    /// ```
    pub fn new(subject: String, device: String, key_thumbprint: String, attributes: Value) -> Self {
        Self {
            subject,
            device,
            key_thumbprint,
            attributes,
        }
    }

    /// Which of the device's keys signed this request: the attestation's `att.role` under
    /// device-signature profile v1 (`docs/rfc-014-devsig-profile-v1.md`).
    ///
    /// Only the exact string `"user_present"` reads as [`KeyRole::UserPresent`]. Anything else —
    /// an absent `role`, another string, a non-string — reads as [`KeyRole::Ambient`], the key
    /// that never prompts. That fallback is the safe direction: a value this crate does not
    /// understand can never be mistaken for a fresh user-presence proof, and an application
    /// that already used `att.role` for its own roles (`"user"`, `"admin"`) keeps working, with
    /// every such device read as ambient.
    ///
    /// ```
    /// use authkestra_devsig::{DeviceIdentity, KeyRole};
    ///
    /// let identity = DeviceIdentity::new(
    ///     "usr_1".to_owned(),
    ///     "dev_1".to_owned(),
    ///     "jkt-1".to_owned(),
    ///     serde_json::json!({ "status": "active", "role": "user_present" }),
    /// );
    /// assert_eq!(identity.key_role(), KeyRole::UserPresent);
    /// ```
    pub fn key_role(&self) -> KeyRole {
        match self.attributes.get("role").and_then(Value::as_str) {
            Some(role) if role == KeyRole::UserPresent.as_str() => KeyRole::UserPresent,
            _ => KeyRole::Ambient,
        }
    }
}

/// Which of a device's keys signed a request (device-signature profile v1, `att.role`).
///
/// A device may enrol two keys: one that signs every ordinary request without asking, and one
/// whose every use is gated by the platform (a biometric or the device credential). A handler
/// that needs proof the user was present for *this* request checks for
/// [`KeyRole::UserPresent`] and otherwise answers
/// [`Refusal::insufficient_user_authentication`](crate::Refusal::insufficient_user_authentication).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyRole {
    /// The key that never prompts (`att.role` absent or `"ambient"`).
    Ambient,
    /// The key whose every signature needed the user (`att.role` = `"user_present"`).
    UserPresent,
}

impl KeyRole {
    /// The wire value in `att.role`: `"ambient"` or `"user_present"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyRole::Ambient => "ambient",
            KeyRole::UserPresent => "user_present",
        }
    }
}
