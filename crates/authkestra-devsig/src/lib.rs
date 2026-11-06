//! `authkestra-devsig` — device-bound signature authentication.
//!
//! This is the fourth request-authentication family, alongside OAuth/OIDC, sessions, and Basic:
//! **per-request proof of possession of a device-bound private key, with the public key and its
//! identity binding travelling in the request itself.** Verification needs no session store, no
//! token introspection, and no per-request network call — any service holding one cached Issuer
//! JWKS can verify a request independently.
//!
//! ## The two credentials
//!
//! Every request carries two JWSes that do different jobs:
//!
//! - **`X-Signature`** — short-lived, single-use, signed by the *device*. Proves possession of
//!   the private key for *this* request.
//! - **`X-Attestation`** — long-lived, reusable, public, signed by the *Issuer*. Binds that key's
//!   RFC 7638 thumbprint (`cnf.jkt`) to an identity and its attributes. This is what
//!   `authkestra-op` mints at enrolment (tracked separately in
//!   [authkestra#136](https://github.com/marcjazz/authkestra/issues/136)); this crate only
//!   verifies attestations, it does not mint them.
//!
//! Neither is sufficient alone: the signature without the attestation is an anonymous key, and
//! the attestation without the signature is exactly the bearer-token pattern this design exists
//! to avoid — see [`VerifyError::MissingCredential`]. Only together, and only after the
//! thumbprint binding is checked, do they authenticate anything. See [`verify`]'s docs for why
//! that check is the one step in the algorithm that cannot be skipped, reordered, or inferred
//! from the others.
//!
//! ## Entry point
//!
//! [`verify`] is a plain async function, deliberately decoupled from any HTTP framework:
//!
//! ```ignore
//! let identity = authkestra_devsig::verify(&request, &config, &jwks, &replay_store).await?;
//! ```
//!
//! ## Profile v1: one wire contract, shared vectors
//!
//! What a request looks like and how a refusal goes out are fixed by device-signature profile
//! v1 (`docs/rfc-014-devsig-profile-v1.md`): the `att` claim is an object with a required
//! `status` and an optional key `role` ([`KeyRole`]), a refusal is
//! `{"error": "<code>"}` with the status and challenge [`Refusal`] gives, and a `qsh` or `bdh`
//! must be present exactly when the request has a query or a body. The conformance vectors in
//! `conformance/devsig-profile-v1/` are run against [`verify_at`] by this crate's tests, and
//! client libraries vendor the same file.
//!
//! ## Framework integration — lives in the adapter crates, per `AGENTS.md`
//!
//! Two extension points exist in `authkestra-engine` today: `AuthMethod` (roadmapped, used only
//! in tests, and its `AuthInput` carries no HTTP request context at all) and
//! `AuthenticationStrategy<I>` (what `Guard<I>`/`JwtStrategy` actually chain, but
//! `authenticate(&self, parts: &Parts)` has no body — and this scheme needs the raw body bytes
//! for the `bdh` check). Neither can express a body-aware verifier today, and deciding which one
//! should grow that capability — or whether a new trait should — is the framework's own
//! architecture call, tracked in
//! [authkestra#137](https://github.com/marcjazz/authkestra/issues/137).
//!
//! This crate stays framework-agnostic (per `AGENTS.md`'s "Framework Agnostic" rule) and exposes
//! only the plain [`verify`] function plus the types it needs. Framework wiring lives in the
//! adapter crates instead:
//!
//! - `authkestra-axum`'s `devsig` feature (see its `devsig` module) ships a `tower::Layer` that
//!   buffers and hashes the body ahead of axum's extraction and injects a verified
//!   [`DeviceIdentity`] into request extensions, plus a thin `FromRequestParts` extractor that
//!   reads it back out.
//! - `authkestra-actix`'s `devsig` feature (see its `devsig` module) ships the equivalent
//!   `actix_web::dev::Transform` middleware and `FromRequest` extractor.
//!
//! Both exist specifically because they need neither `authkestra-engine` trait to exist yet, and
//! migrating to whichever trait the maintainer lands on is a matter of swapping which caller
//! builds a [`SignedRequest`] and calls [`verify`] — the algorithm itself is unaffected either
//! way. See each adapter crate's `devsig` module docs for why an `AuthenticationStrategy<I>`
//! impl is deliberately *not* provided today.

mod attestation;
mod config;
mod eddsa;
mod error;
mod identity;
mod jwks;
mod jws_util;
mod profile;
mod replay;
mod request;
mod signature;
mod verify;

pub use config::VerifierConfig;
pub use error::VerifyError;
pub use identity::{DeviceIdentity, KeyRole};
pub use jwks::IssuerJwks;
pub use profile::{
    Refusal, ATTESTATION_HEADER, DEVICE_REVOKED, INSUFFICIENT_USER_AUTHENTICATION,
    MAX_SIGNATURE_LIFETIME, PROFILE_VERSION, RECOMMENDED_CLOCK_SKEW, REFUSAL_CONTENT_TYPE,
    SIGNATURE_HEADER, WWW_AUTHENTICATE_SCHEME,
};
pub use replay::{InMemoryReplayStore, ReplayError, ReplayStore, UnavailableReplayStore};
pub use request::SignedRequest;
pub use verify::{verify, verify_at};
pub mod builder;
pub use builder::{DevSig, DevSigBuilder};
