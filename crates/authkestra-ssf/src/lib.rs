//! `authkestra-ssf` — Shared Signals Framework ingestion for authkestra.
//!
//! An identity provider, an EDR agent, or any other cooperating service can tell this process
//! that something about a user changed *out of band*: their session was revoked, their password
//! was reset, their laptop fell out of compliance. The wire format for that is a **Security
//! Event Token** ([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)) — a signed JWT whose
//! payload is a set of events — delivered over HTTP push
//! ([RFC 8935](https://www.rfc-editor.org/rfc/rfc8935)), with the event vocabulary defined by
//! [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-specification-1_0.html).
//!
//! This crate covers the *receiving* half of that picture, end to end but no further:
//!
//! | Capability | Status |
//! | --- | --- |
//! | Parse and validate a SET (RFC 8417 claim profile, explicit `typ`, signature, issuer, audience, freshness, replay) | [`SetVerifier`] |
//! | Structured subject identifiers ([RFC 9493](https://www.rfc-editor.org/rfc/rfc9493)) | [`SubjectIdentifier`] |
//! | Typed CAEP 1.0 events, with unknown event types preserved | [`CaepEvent`] |
//! | RFC 8935 push delivery semantics (202 / 400 with a registered error code) | [`PushReceiver`] |
//! | **Revoking or attenuating a live session when an event arrives** | **not implemented** |
//! | **Middleware that rejects tokens invalidated by a CAEP event** | **not implemented** |
//!
//! The last two rows are the second and third acceptance criteria of
//! [authkestra#25](https://github.com/marcjazz/authkestra/issues/25) and are follow-up work.
//! Until they land, a [`SetHandler`] is where a deployment puts its own reaction to an event —
//! the events themselves are fully decoded and delivered.
//!
//! ## Framework wiring
//!
//! There is none here, on purpose. Per the workspace `AGENTS.md` "Framework Agnostic" rule,
//! [`PushReceiver::receive`] takes a content type and a byte slice and returns a
//! [`PushResponse`] describing the status, headers and body to send; the axum and actix
//! adapters that turn that into a route are a follow-up.
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use authkestra_ssf::{
//!     InMemorySetReplayGuard, LoggingHandler, PushReceiver, SetVerifier,
//! };
//! use jsonwebtoken::{Algorithm, DecodingKey};
//!
//! # async fn example(transmitter_key: DecodingKey, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let verifier = SetVerifier::builder("https://idp.example.com/")
//!     .audience("https://sp.example.com/caep")
//!     .algorithms([Algorithm::EdDSA])
//!     .key(transmitter_key)
//!     .max_age(Duration::from_secs(60 * 60))
//!     .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(
//!         60 * 60,
//!     ))))
//!     .build()?;
//!
//! let receiver = PushReceiver::new(Arc::new(verifier)).with_handler(Arc::new(LoggingHandler));
//!
//! let response = receiver
//!     .receive(Some("application/secevent+jwt"), body)
//!     .await;
//! assert_eq!(response.status(), 202);
//! # Ok(())
//! # }
//! ```

mod caep;
mod error;
mod keys;
mod receiver;
mod replay;
mod set;
mod subject;
mod verify;

pub use caep::{
    AssuranceLevel, AssuranceLevelChange, CaepEvent, CaepMetadata, ChangeDirection, ChangeType,
    ComplianceStatus, CredentialChange, CredentialType, DeviceComplianceChange, EventDecodeError,
    InitiatingEntity, LocalizedMessage, SessionRevoked, TokenClaimsChange, CAEP_EVENT_TYPE_PREFIX,
    EVENT_TYPE_ASSURANCE_LEVEL_CHANGE, EVENT_TYPE_CREDENTIAL_CHANGE,
    EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE, EVENT_TYPE_SESSION_REVOKED,
    EVENT_TYPE_TOKEN_CLAIMS_CHANGE,
};
pub use error::{SetError, SetErrorCode};
pub use keys::{KeyResolveError, SetKeyResolver, SingleKeyResolver, StaticKeyResolver};
pub use receiver::{
    HandlerError, LoggingHandler, PushReceiver, PushResponse, SetHandler, SsfEventHandler,
    DEFAULT_MAX_BODY_BYTES, ERROR_CONTENT_LANGUAGE, ERROR_CONTENT_TYPE,
};
pub use replay::{InMemorySetReplayGuard, SetReplayGuard};
pub use set::{Audience, SecurityEventToken, SET_MEDIA_TYPE, SET_TYP};
pub use subject::SubjectIdentifier;
pub use verify::{SetVerifier, SetVerifierBuilder, SetVerifierError, VerifiedSet};

#[cfg(feature = "session")]
pub mod session;
#[cfg(feature = "session")]
pub use session::SessionRevocationHandler;
