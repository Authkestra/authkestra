//! Authkestra is a modular authentication framework for Rust.
//!
//! This crate serves as a facade, re-exporting functionality from other `authkestra-*` crates
//! based on enabled features.

/// The engine: `Engine`, the auth methods, the flows, the token machinery
/// and the stores.
///
/// This is the *only* name the facade gives `authkestra-engine`. It used to
/// also be re-exported as `flow` and `token`, from when `authkestra-flow` and
/// `authkestra-token` were separate crates (RFC-001, since merged into
/// `authkestra-engine`). Those aliases outlived the crates they were named
/// after: all three resolved to the same crate, so `authkestra::flow::` handed
/// you the token and session machinery too, and `token` was gated on
/// `feature = "token"` while re-exporting everything that feature does not
/// cover. Both are gone — reach any of it through `core`.
#[cfg(feature = "engine")]
pub use authkestra_engine as core;

/// Type alias for the Engine to support the Authkestra::builder() pattern.
#[cfg(feature = "engine")]
pub type Authkestra<S = authkestra_engine::Missing, T = authkestra_engine::Missing> =
    authkestra_engine::Engine<S, T>;

/// Session, token and credential stores, plus the memory/Redis/SQL backends.
///
/// A short path to [`core::store`]; which backends exist inside it is decided
/// by the engine's own feature gates, not re-gated here. The gate is the set
/// of storage backends — it was previously `feature = "session"` alone, with
/// a *second* copy of the same module exported as `persistence` under a wider
/// gate, so which name worked depended on which feature you happened to
/// enable. The `session` feature itself no longer exists; the store traits
/// live in [`core::auth`] and are reachable without picking a backend.
#[cfg(any(
    feature = "memory",
    feature = "redis",
    feature = "sql-postgres",
    feature = "sql-mysql",
    feature = "sql-sqlite"
))]
pub use authkestra_engine::store;

/// WebAuthn passkey authentication.
#[cfg(feature = "webauthn")]
pub use authkestra_engine::webauthn;

/// Time-based One-Time Password (TOTP) authentication.
#[cfg(feature = "totp")]
pub use authkestra_engine::totp;

#[cfg(feature = "oidc")]
pub use authkestra_oidc as oidc;

/// Cedar policy engine for declarative ABAC authorization, wired across resource server guards,
/// Axum/Actix extractors, and MCP tool enforcement.
#[cfg(feature = "policy")]
pub use authkestra_policy as policy;

/// Shared Signals Framework (RFC 8417 / RFC 8935) and OpenID CAEP event ingestion with
/// push receiver routes and session store revocation.
#[cfg(feature = "ssf")]
pub use authkestra_ssf as ssf;

#[cfg(feature = "axum")]
pub use authkestra_axum as axum;

#[cfg(feature = "actix")]
pub use authkestra_actix as actix;

/// The OpenID Provider server: `OpConfig`, `OpStore` and the handlers the
/// adapters' `op` routes are built from.
///
/// Re-exported alongside the adapters' `op` feature because those routes are
/// configured with types from this crate — forwarding the feature without it
/// would leave the endpoints reachable but unconfigurable (#325).
#[cfg(feature = "op")]
pub use authkestra_op as op;

/// Device and service signatures: `DeviceIdentity`, `SignedRequest` and the
/// verification entry points the adapters' `devsig` layers wrap.
#[cfg(feature = "devsig")]
pub use authkestra_devsig as devsig;

/// Embedded Model Context Protocol (MCP) server security guard, JCS parameter binding,
/// cryptographic step-up approval, and zero-trust downstream token vault.
#[cfg(feature = "mcp")]
pub use authkestra_mcp as mcp;

/// Authentication providers.
pub mod providers {
    #[cfg(feature = "github")]
    pub use authkestra_providers::github;

    #[cfg(feature = "google")]
    pub use authkestra_providers::google;

    #[cfg(feature = "discord")]
    pub use authkestra_providers::discord;
}
